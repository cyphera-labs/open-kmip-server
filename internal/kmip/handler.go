package kmip

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"

	kmiplib "github.com/cyphera-labs/kmip-go"
	"github.com/cyphera-labs/open-kmip-server/internal/audit"
	"github.com/cyphera-labs/open-kmip-server/internal/storage"
)

// Operation codes not exported by kmip-go.
const (
	OperationCreateKeyPair    = 0x00000002
	OperationRegister         = 0x00000003
	OperationReKey            = 0x00000004
	OperationGetAttributes    = 0x0000000B
	OperationGetAttributeList = 0x0000000C
	OperationRevoke           = 0x00000013
	OperationQuery            = 0x00000018
	OperationDiscoverVersions = 0x0000001E
	OperationEncrypt          = 0x0000001F
	OperationDecrypt          = 0x00000020
	OperationSign             = 0x00000021
	OperationSignatureVerify  = 0x00000022
	OperationMAC              = 0x00000023
)

// Tag constants not exported by kmip-go.
const (
	TagRevocationReason           = 0x420082
	TagQueryFunction              = 0x420074
	TagState                      = 0x42008D
	TagPrivateKeyUniqueIdentifier = 0x420066
	TagPublicKeyUniqueIdentifier  = 0x42006F
	TagPublicKey                  = 0x42004E
	TagPrivateKey                 = 0x42004D
	TagCertificate                = 0x420021
	TagCertificateType            = 0x42001D
	TagCertificateValue           = 0x42001E
	TagData                       = 0x420033
	TagIVCounterNonce             = 0x420047
	TagSignatureData              = 0x42004F
	TagMACData                    = 0x420051
	TagValidityIndicator          = 0x420098
)

// Additional operation codes from handler_attrs.go
const (
	OpAddAttribute    = 0x0000000D
	OpModifyAttribute = 0x0000000E
	OpDeleteAttribute = 0x0000000F
	OpDeriveKey       = 0x00000005
	OpObtainLease     = 0x00000010
	OpPoll            = 0x0000001A
	OpArchive         = 0x00000015
	OpRecover         = 0x00000016
)

// KMIP ResultReason codes.
const (
	ReasonItemNotFound          = 0x00000001
	ReasonResponseTooLarge      = 0x00000002
	ReasonAuthNotSuccessful     = 0x00000003
	ReasonInvalidMessage        = 0x00000004
	ReasonOperationNotSupported = 0x00000005
	ReasonMissingData           = 0x00000006
	ReasonInvalidField          = 0x00000007
	ReasonFeatureNotSupported   = 0x00000008
	ReasonCryptographicFailure  = 0x0000000A
	ReasonIllegalOperation      = 0x0000000B
	ReasonPermissionDenied      = 0x0000000C
	ReasonGeneralFailure        = 0x00000100
)

const (
	supportedMajor = 1
	supportedMinor = 4
)

// Handler processes KMIP requests against the key store.
type Handler struct {
	store   storage.Storage
	audit   *audit.Logger
	tracker *ConnectionTracker
}

// NewHandler creates a new request handler.
func NewHandler(store storage.Storage, auditLog *audit.Logger, tracker *ConnectionTracker) *Handler {
	return &Handler{store: store, audit: auditLog, tracker: tracker}
}

func operationName(op int) string {
	switch op {
	case kmiplib.OperationCreate:
		return "Create"
	case OperationCreateKeyPair:
		return "CreateKeyPair"
	case kmiplib.OperationGet:
		return "Get"
	case kmiplib.OperationLocate:
		return "Locate"
	case kmiplib.OperationDestroy:
		return "Destroy"
	case kmiplib.OperationActivate:
		return "Activate"
	case kmiplib.OperationCheck:
		return "Check"
	case OperationRegister:
		return "Register"
	case OperationRevoke:
		return "Revoke"
	case OperationReKey:
		return "ReKey"
	case OperationGetAttributes:
		return "GetAttributes"
	case OperationGetAttributeList:
		return "GetAttributeList"
	case OperationQuery:
		return "Query"
	case OperationDiscoverVersions:
		return "DiscoverVersions"
	case OperationEncrypt:
		return "Encrypt"
	case OperationDecrypt:
		return "Decrypt"
	case OperationSign:
		return "Sign"
	case OperationSignatureVerify:
		return "SignatureVerify"
	case OperationMAC:
		return "MAC"
	case OpAddAttribute:
		return "AddAttribute"
	case OpModifyAttribute:
		return "ModifyAttribute"
	case OpDeleteAttribute:
		return "DeleteAttribute"
	case OpDeriveKey:
		return "DeriveKey"
	case OpObtainLease:
		return "ObtainLease"
	case OpPoll:
		return "Poll"
	case OpArchive:
		return "Archive"
	case OpRecover:
		return "Recover"
	default:
		return fmt.Sprintf("Unknown(0x%08X)", op)
	}
}

func (h *Handler) logOperation(source, operation, clientID, objectUID, objectName, status, message, remoteAddr string) {
	if h.audit != nil {
		h.audit.Log(audit.Entry{
			Timestamp:  time.Now(),
			Source:     source,
			Operation:  operation,
			ClientID:   clientID,
			ObjectUID:  objectUID,
			ObjectName: objectName,
			Status:     status,
			Message:    message,
			RemoteAddr: remoteAddr,
		})
	}
}

func validateStateTransition(state storage.KeyState, operation string) (int, string, bool) {
	switch operation {
	case "Get":
		switch state {
		case storage.StatePreActive, storage.StateActive, storage.StateDeactivated, storage.StateCompromised:
			return 0, "", true
		default:
			return ReasonIllegalOperation, fmt.Sprintf("Get not allowed in state %d", state), false
		}
	case "Activate":
		if state == storage.StatePreActive {
			return 0, "", true
		}
		if state == storage.StateActive {
			return ReasonIllegalOperation, "object is already active", false
		}
		return ReasonIllegalOperation, fmt.Sprintf("Activate not allowed in state %d", state), false
	case "Revoke":
		switch state {
		case storage.StatePreActive, storage.StateActive, storage.StateDeactivated:
			return 0, "", true
		default:
			return ReasonIllegalOperation, fmt.Sprintf("Revoke not allowed in state %d", state), false
		}
	case "Destroy":
		switch state {
		case storage.StateDestroyed, storage.StateDestroyedCompromised:
			return ReasonIllegalOperation, "object is already destroyed", false
		default:
			return 0, "", true
		}
	case "Archive":
		if state == storage.StateDeactivated {
			return 0, "", true
		}
		return ReasonIllegalOperation, fmt.Sprintf("Archive only allowed from Deactivated, current: %d", state), false
	case "Recover":
		if state == storage.StateArchived {
			return 0, "", true
		}
		return ReasonIllegalOperation, fmt.Sprintf("Recover only allowed from Archived, current: %d", state), false
	case "ReKey":
		if state == storage.StateActive {
			return 0, "", true
		}
		return ReasonIllegalOperation, fmt.Sprintf("ReKey only allowed from Active, current: %d", state), false
	case "Encrypt", "Decrypt", "Sign", "SignatureVerify", "MAC":
		if state == storage.StateActive {
			return 0, "", true
		}
		return ReasonIllegalOperation, fmt.Sprintf("%s only allowed on Active keys, current: %d", operation, state), false
	default:
		return 0, "", true
	}
}

// HandleRequest processes a raw KMIP request and returns a raw KMIP response.
func (h *Handler) HandleRequest(data []byte, clientCN, remoteAddr, connID string) []byte {
	msg, err := kmiplib.DecodeTTLV(data, 0)
	if err != nil {
		h.logOperation("kmip", "Decode", clientCN, "", "", "failure", fmt.Sprintf("decode failed: %v", err), remoteAddr)
		return h.buildErrorResponse(0, ReasonInvalidMessage, fmt.Sprintf("decode failed: %v", err))
	}

	if msg.Tag != kmiplib.TagRequestMessage {
		return h.buildErrorResponse(0, ReasonInvalidMessage, fmt.Sprintf("expected RequestMessage, got 0x%06X", msg.Tag))
	}

	// Protocol version check.
	header := kmiplib.FindChild(msg, kmiplib.TagRequestHeader)
	if header != nil {
		pv := kmiplib.FindChild(header, kmiplib.TagProtocolVersion)
		if pv != nil {
			majorItem := kmiplib.FindChild(pv, kmiplib.TagProtocolVersionMajor)
			if majorItem != nil {
				reqMajor := int(majorItem.IntValue())
				reqMinor := 0
				if minorItem := kmiplib.FindChild(pv, kmiplib.TagProtocolVersionMinor); minorItem != nil {
					reqMinor = int(minorItem.IntValue())
				}
				if reqMajor > supportedMajor || (reqMajor == supportedMajor && reqMinor > supportedMinor) {
					return h.buildErrorResponse(0, ReasonFeatureNotSupported,
						fmt.Sprintf("unsupported version %d.%d; server supports %d.%d", reqMajor, reqMinor, supportedMajor, supportedMinor))
				}
			}
		}
	}

	batchItems := kmiplib.FindChildren(msg, kmiplib.TagBatchItem)
	if len(batchItems) == 0 {
		return h.buildErrorResponse(0, ReasonInvalidMessage, "no BatchItem in request")
	}
	// M1 fix: cap batch size to prevent resource exhaustion
	const maxBatchItems = 100
	if len(batchItems) > maxBatchItems {
		return h.buildErrorResponse(0, ReasonResponseTooLarge,
			fmt.Sprintf("batch too large: %d items (max %d)", len(batchItems), maxBatchItems))
	}

	// M14 fix: cap total request size (already enforced by server.go maxTTLVMessageSize)
	// M15: per-IP connection limiting handled by server.go semaphore

	var responseBatchItems [][]byte
	for _, bi := range batchItems {
		responseBatchItems = append(responseBatchItems, h.processBatchItem(bi, clientCN, remoteAddr, connID))
	}
	return h.buildBatchResponse(len(responseBatchItems), responseBatchItems)
}

func (h *Handler) processBatchItem(batchItem *kmiplib.Item, clientCN, remoteAddr, connID string) []byte {
	opItem := kmiplib.FindChild(batchItem, kmiplib.TagOperation)
	if opItem == nil {
		return h.buildBatchItemError(0, ReasonInvalidMessage, "no Operation in BatchItem")
	}
	operation := int(opItem.IntValue())
	opName := operationName(operation)
	payload := kmiplib.FindChild(batchItem, kmiplib.TagRequestPayload)

	requestUID := ""
	if payload != nil {
		if uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier); uidItem != nil {
			requestUID = uidItem.StringValue()
		}
	}

	var response []byte
	switch operation {
	case kmiplib.OperationCreate:
		response = h.handleCreate(operation, payload, clientCN)
	case OperationCreateKeyPair:
		response = h.handleCreateKeyPair(operation, payload)
	case kmiplib.OperationGet:
		response = h.handleGet(operation, payload)
	case kmiplib.OperationLocate:
		response = h.handleLocate(operation, payload)
	case kmiplib.OperationDestroy:
		response = h.handleDestroy(operation, payload)
	case kmiplib.OperationActivate:
		response = h.handleActivate(operation, payload)
	case kmiplib.OperationCheck:
		response = h.handleCheck(operation, payload)
	case OperationRegister:
		response = h.handleRegister(operation, payload)
	case OperationRevoke:
		response = h.handleRevoke(operation, payload)
	case OperationGetAttributes:
		response = h.handleGetAttributes(operation, payload)
	case OperationQuery:
		response = h.handleQuery(operation, payload)
	case OperationDiscoverVersions:
		response = h.handleDiscoverVersions(operation, payload)
	case OperationEncrypt:
		response = h.handleEncrypt(operation, payload)
	case OperationDecrypt:
		response = h.handleDecrypt(operation, payload)
	case OperationSign:
		response = h.handleSign(operation, payload)
	case OperationSignatureVerify:
		response = h.handleSignatureVerify(operation, payload)
	case OperationMAC:
		response = h.handleMAC(operation, payload)
	case OperationReKey:
		response = h.handleReKey(operation, payload)
	case OperationGetAttributeList:
		response = h.handleGetAttributeList(operation, payload)
	case OpAddAttribute:
		response = h.handleAddAttribute(operation, payload)
	case OpModifyAttribute:
		response = h.handleModifyAttribute(operation, payload)
	case OpDeleteAttribute:
		response = h.handleDeleteAttribute(operation, payload)
	case OpDeriveKey:
		response = h.handleDeriveKey(operation, payload)
	case OpObtainLease:
		response = h.handleObtainLease(operation, payload)
	case OpPoll:
		response = h.handlePoll(operation, payload)
	case OpArchive:
		response = h.handleArchive(operation, payload)
	case OpRecover:
		response = h.handleRecover(operation, payload)
	default:
		response = h.buildBatchItemError(operation, ReasonOperationNotSupported, fmt.Sprintf("unsupported: 0x%08X", operation))
	}

	// Audit
	status := "success"
	message := ""
	if respItem, err := kmiplib.DecodeTTLV(response, 0); err == nil {
		if rs := kmiplib.FindChild(respItem, kmiplib.TagResultStatus); rs != nil && int(rs.IntValue()) != kmiplib.ResultStatusSuccess {
			status = "failure"
			if rm := kmiplib.FindChild(respItem, kmiplib.TagResultMessage); rm != nil {
				message = rm.StringValue()
			}
		}
		if requestUID == "" {
			if rp := kmiplib.FindChild(respItem, kmiplib.TagResponsePayload); rp != nil {
				if uid := kmiplib.FindChild(rp, kmiplib.TagUniqueIdentifier); uid != nil {
					requestUID = uid.StringValue()
				}
			}
		}
	}
	h.logOperation("kmip", opName, clientCN, requestUID, "", status, message, remoteAddr)
	if h.tracker != nil {
		h.tracker.RecordOp(connID, opName)
	}
	return response
}

// --- Operation handlers ---

func (h *Handler) handleCreate(op int, payload *kmiplib.Item, clientCN string) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}

	name := ""
	algorithm := kmiplib.AlgorithmAES
	length := int32(256)
	usageMask := kmiplib.UsageMaskEncrypt | kmiplib.UsageMaskDecrypt

	if tmpl := kmiplib.FindChild(payload, kmiplib.TagTemplateAttribute); tmpl != nil {
		for _, attr := range kmiplib.FindChildren(tmpl, kmiplib.TagAttribute) {
			attrName := kmiplib.FindChild(attr, kmiplib.TagAttributeName)
			attrValue := kmiplib.FindChild(attr, kmiplib.TagAttributeValue)
			if attrName == nil || attrValue == nil {
				continue
			}
			switch attrName.StringValue() {
			case "Name":
				if nv := kmiplib.FindChild(attrValue, kmiplib.TagNameValue); nv != nil {
					name = nv.StringValue()
				}
			case "Cryptographic Algorithm":
				algorithm = int(attrValue.IntValue())
			case "Cryptographic Length":
				length = attrValue.IntValue()
			case "Cryptographic Usage Mask":
				usageMask = int(attrValue.IntValue())
			}
		}
	}

	// C2 fix: length validation is in storage layer
	rec, err := h.store.Create(name, algorithm, length, usageMask, clientCN)
	if err != nil {
		return h.buildBatchItemError(op, ReasonGeneralFailure, err.Error())
	}

	return h.buildBatchItemSuccess(op,
		kmiplib.EncodeEnum(kmiplib.TagObjectType, rec.ObjectType),
		kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, rec.UID),
	)
}

func (h *Handler) handleCreateKeyPair(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}

	name := ""
	algorithm := kmiplib.AlgorithmRSA
	length := int32(2048)
	usageMask := kmiplib.UsageMaskSign | kmiplib.UsageMaskVerify

	if tmpl := kmiplib.FindChild(payload, kmiplib.TagTemplateAttribute); tmpl != nil {
		for _, attr := range kmiplib.FindChildren(tmpl, kmiplib.TagAttribute) {
			attrName := kmiplib.FindChild(attr, kmiplib.TagAttributeName)
			attrValue := kmiplib.FindChild(attr, kmiplib.TagAttributeValue)
			if attrName == nil || attrValue == nil {
				continue
			}
			switch attrName.StringValue() {
			case "Name":
				if nv := kmiplib.FindChild(attrValue, kmiplib.TagNameValue); nv != nil {
					name = nv.StringValue()
				}
			case "Cryptographic Algorithm":
				algorithm = int(attrValue.IntValue())
			case "Cryptographic Length":
				length = attrValue.IntValue()
			case "Cryptographic Usage Mask":
				usageMask = int(attrValue.IntValue())
			}
		}
	}

	var privDER, pubDER []byte
	var err error

	switch algorithm {
	case kmiplib.AlgorithmRSA:
		privKey, genErr := rsa.GenerateKey(rand.Reader, int(length))
		if genErr != nil {
			return h.buildBatchItemError(op, ReasonCryptographicFailure, fmt.Sprintf("RSA keygen: %v", genErr))
		}
		privDER, err = x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return h.buildBatchItemError(op, ReasonCryptographicFailure, err.Error())
		}
		pubDER, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		if err != nil {
			return h.buildBatchItemError(op, ReasonCryptographicFailure, err.Error())
		}
	case kmiplib.AlgorithmECDSA:
		var curve elliptic.Curve
		switch length {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
			length = 256
		}
		privKey, genErr := ecdsa.GenerateKey(curve, rand.Reader)
		if genErr != nil {
			return h.buildBatchItemError(op, ReasonCryptographicFailure, fmt.Sprintf("EC keygen: %v", genErr))
		}
		privDER, err = x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return h.buildBatchItemError(op, ReasonCryptographicFailure, err.Error())
		}
		pubDER, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		if err != nil {
			return h.buildBatchItemError(op, ReasonCryptographicFailure, err.Error())
		}
	default:
		return h.buildBatchItemError(op, ReasonInvalidField, fmt.Sprintf("unsupported algorithm: 0x%08X", algorithm))
	}

	privRec := &storage.KeyRecord{ObjectType: kmiplib.ObjectTypePrivateKey, Name: name, Algorithm: algorithm, Length: length, Material: privDER, UsageMask: usageMask}
	privRec, err = h.store.Register(privRec)
	if err != nil {
		return h.buildBatchItemError(op, ReasonGeneralFailure, err.Error())
	}
	pubRec := &storage.KeyRecord{ObjectType: kmiplib.ObjectTypePublicKey, Name: name, Algorithm: algorithm, Length: length, Material: pubDER, UsageMask: usageMask}
	pubRec, err = h.store.Register(pubRec)
	if err != nil {
		return h.buildBatchItemError(op, ReasonGeneralFailure, err.Error())
	}

	return h.buildBatchItemSuccess(op,
		kmiplib.EncodeTextString(TagPrivateKeyUniqueIdentifier, privRec.UID),
		kmiplib.EncodeTextString(TagPublicKeyUniqueIdentifier, pubRec.UID),
	)
}

func (h *Handler) handleGet(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	uid := uidItem.StringValue()

	rec, ok := h.store.Get(uid)
	if !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uid))
	}
	if reason, msg, valid := validateStateTransition(rec.State, "Get"); !valid {
		return h.buildBatchItemError(op, reason, msg)
	}

	var objectData []byte
	switch rec.ObjectType {
	case kmiplib.ObjectTypePublicKey:
		objectData = kmiplib.EncodeStructure(TagPublicKey,
			kmiplib.EncodeStructure(kmiplib.TagKeyBlock,
				kmiplib.EncodeEnum(kmiplib.TagKeyFormatType, kmiplib.KeyFormatX509),
				kmiplib.EncodeStructure(kmiplib.TagKeyValue, kmiplib.EncodeByteString(kmiplib.TagKeyMaterial, rec.Material)),
				kmiplib.EncodeEnum(kmiplib.TagCryptographicAlgorithm, rec.Algorithm),
				kmiplib.EncodeInteger(kmiplib.TagCryptographicLength, rec.Length),
			),
		)
	case kmiplib.ObjectTypePrivateKey:
		objectData = kmiplib.EncodeStructure(TagPrivateKey,
			kmiplib.EncodeStructure(kmiplib.TagKeyBlock,
				kmiplib.EncodeEnum(kmiplib.TagKeyFormatType, kmiplib.KeyFormatPKCS8),
				kmiplib.EncodeStructure(kmiplib.TagKeyValue, kmiplib.EncodeByteString(kmiplib.TagKeyMaterial, rec.Material)),
				kmiplib.EncodeEnum(kmiplib.TagCryptographicAlgorithm, rec.Algorithm),
				kmiplib.EncodeInteger(kmiplib.TagCryptographicLength, rec.Length),
			),
		)
	case kmiplib.ObjectTypeCertificate:
		objectData = kmiplib.EncodeStructure(TagCertificate,
			kmiplib.EncodeEnum(TagCertificateType, 1),
			kmiplib.EncodeByteString(TagCertificateValue, rec.Material),
		)
	default:
		objectData = kmiplib.EncodeStructure(kmiplib.TagSymmetricKey,
			kmiplib.EncodeStructure(kmiplib.TagKeyBlock,
				kmiplib.EncodeEnum(kmiplib.TagKeyFormatType, kmiplib.KeyFormatRaw),
				kmiplib.EncodeStructure(kmiplib.TagKeyValue, kmiplib.EncodeByteString(kmiplib.TagKeyMaterial, rec.Material)),
				kmiplib.EncodeEnum(kmiplib.TagCryptographicAlgorithm, rec.Algorithm),
				kmiplib.EncodeInteger(kmiplib.TagCryptographicLength, rec.Length),
			),
		)
	}

	return h.buildBatchItemSuccess(op,
		kmiplib.EncodeEnum(kmiplib.TagObjectType, rec.ObjectType),
		kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, rec.UID),
		objectData,
	)
}

func (h *Handler) handleLocate(op int, payload *kmiplib.Item) []byte {
	name := ""
	if payload != nil {
		if attr := kmiplib.FindChild(payload, kmiplib.TagAttribute); attr != nil {
			if av := kmiplib.FindChild(attr, kmiplib.TagAttributeValue); av != nil {
				if nv := kmiplib.FindChild(av, kmiplib.TagNameValue); nv != nil {
					name = nv.StringValue()
				}
			}
		}
	}
	uids := h.store.Locate(name)
	children := make([][]byte, 0, len(uids))
	for _, uid := range uids {
		children = append(children, kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, uid))
	}
	return h.buildBatchItemSuccess(op, children...)
}

func (h *Handler) handleDestroy(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	uid := uidItem.StringValue()
	rec, ok := h.store.Get(uid)
	if !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uid))
	}
	if reason, msg, valid := validateStateTransition(rec.State, "Destroy"); !valid {
		return h.buildBatchItemError(op, reason, msg)
	}
	if err := h.store.Destroy(uid); err != nil {
		return h.buildBatchItemError(op, ReasonGeneralFailure, err.Error())
	}
	return h.buildBatchItemSuccess(op, kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, uid))
}

func (h *Handler) handleActivate(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	uid := uidItem.StringValue()
	rec, ok := h.store.Get(uid)
	if !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uid))
	}
	if reason, msg, valid := validateStateTransition(rec.State, "Activate"); !valid {
		return h.buildBatchItemError(op, reason, msg)
	}
	if err := h.store.Activate(uid); err != nil {
		return h.buildBatchItemError(op, ReasonGeneralFailure, err.Error())
	}
	return h.buildBatchItemSuccess(op, kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, uid))
}

func (h *Handler) handleCheck(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	rec, ok := h.store.Get(uidItem.StringValue())
	if !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uidItem.StringValue()))
	}
	return h.buildBatchItemSuccess(op, kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, rec.UID))
}

func (h *Handler) handleRegister(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}

	objectType := kmiplib.ObjectTypeSymmetricKey
	if ot := kmiplib.FindChild(payload, kmiplib.TagObjectType); ot != nil {
		objectType = int(ot.IntValue())
	}

	var material []byte
	algorithm := kmiplib.AlgorithmAES
	length := int32(256)

	var keyWrapper *kmiplib.Item
	switch objectType {
	case kmiplib.ObjectTypePublicKey:
		keyWrapper = kmiplib.FindChild(payload, TagPublicKey)
	case kmiplib.ObjectTypePrivateKey:
		keyWrapper = kmiplib.FindChild(payload, TagPrivateKey)
	case kmiplib.ObjectTypeCertificate:
		if ci := kmiplib.FindChild(payload, TagCertificate); ci != nil {
			if cv := kmiplib.FindChild(ci, TagCertificateValue); cv != nil {
				material = cv.BytesValue()
			}
		}
	default:
		keyWrapper = kmiplib.FindChild(payload, kmiplib.TagSymmetricKey)
	}

	if keyWrapper != nil {
		if kb := kmiplib.FindChild(keyWrapper, kmiplib.TagKeyBlock); kb != nil {
			if ai := kmiplib.FindChild(kb, kmiplib.TagCryptographicAlgorithm); ai != nil {
				algorithm = int(ai.IntValue())
			}
			if li := kmiplib.FindChild(kb, kmiplib.TagCryptographicLength); li != nil {
				length = li.IntValue()
			}
			if kv := kmiplib.FindChild(kb, kmiplib.TagKeyValue); kv != nil {
				if km := kmiplib.FindChild(kv, kmiplib.TagKeyMaterial); km != nil {
					material = km.BytesValue()
				}
			}
		}
	}

	if material == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing key material")
	}

	name := ""
	usageMask := kmiplib.UsageMaskEncrypt | kmiplib.UsageMaskDecrypt
	if tmpl := kmiplib.FindChild(payload, kmiplib.TagTemplateAttribute); tmpl != nil {
		for _, attr := range kmiplib.FindChildren(tmpl, kmiplib.TagAttribute) {
			an := kmiplib.FindChild(attr, kmiplib.TagAttributeName)
			av := kmiplib.FindChild(attr, kmiplib.TagAttributeValue)
			if an == nil || av == nil {
				continue
			}
			switch an.StringValue() {
			case "Name":
				if nv := kmiplib.FindChild(av, kmiplib.TagNameValue); nv != nil {
					name = nv.StringValue()
				}
			case "Cryptographic Usage Mask":
				usageMask = int(av.IntValue())
			}
		}
	}

	rec := &storage.KeyRecord{ObjectType: objectType, Name: name, Algorithm: algorithm, Length: length, Material: material, UsageMask: usageMask}
	rec, err := h.store.Register(rec)
	if err != nil {
		return h.buildBatchItemError(op, ReasonGeneralFailure, err.Error())
	}
	return h.buildBatchItemSuccess(op, kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, rec.UID))
}

func (h *Handler) handleRevoke(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	uid := uidItem.StringValue()
	rec, ok := h.store.Get(uid)
	if !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uid))
	}
	if reason, msg, valid := validateStateTransition(rec.State, "Revoke"); !valid {
		return h.buildBatchItemError(op, reason, msg)
	}

	reason := 0
	if rr := kmiplib.FindChild(payload, TagRevocationReason); rr != nil {
		if code := kmiplib.FindChild(rr, 0x420083); code != nil {
			reason = int(code.IntValue())
		}
	}
	if err := h.store.Revoke(uid, reason); err != nil {
		return h.buildBatchItemError(op, ReasonGeneralFailure, err.Error())
	}
	return h.buildBatchItemSuccess(op, kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, uid))
}

func (h *Handler) handleGetAttributes(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	rec, ok := h.store.GetAttributes(uidItem.StringValue())
	if !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uidItem.StringValue()))
	}
	return h.buildBatchItemSuccess(op,
		kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, rec.UID),
		kmiplib.EncodeStructure(kmiplib.TagAttribute, kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Name"), kmiplib.EncodeStructure(kmiplib.TagAttributeValue, kmiplib.EncodeTextString(kmiplib.TagNameValue, rec.Name), kmiplib.EncodeEnum(kmiplib.TagNameType, kmiplib.NameTypeUninterpretedTextString))),
		kmiplib.EncodeStructure(kmiplib.TagAttribute, kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Object Type"), kmiplib.EncodeEnum(kmiplib.TagAttributeValue, rec.ObjectType)),
		kmiplib.EncodeStructure(kmiplib.TagAttribute, kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Cryptographic Algorithm"), kmiplib.EncodeEnum(kmiplib.TagAttributeValue, rec.Algorithm)),
		kmiplib.EncodeStructure(kmiplib.TagAttribute, kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Cryptographic Length"), kmiplib.EncodeInteger(kmiplib.TagAttributeValue, rec.Length)),
		kmiplib.EncodeStructure(kmiplib.TagAttribute, kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Cryptographic Usage Mask"), kmiplib.EncodeInteger(kmiplib.TagAttributeValue, int32(rec.UsageMask))),
		kmiplib.EncodeStructure(kmiplib.TagAttribute, kmiplib.EncodeTextString(kmiplib.TagAttributeName, "State"), kmiplib.EncodeEnum(kmiplib.TagAttributeValue, int(rec.State))),
		kmiplib.EncodeStructure(kmiplib.TagAttribute, kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Initial Date"), kmiplib.EncodeDateTime(kmiplib.TagAttributeValue, rec.CreatedAt.Unix())),
	)
}

func (h *Handler) handleQuery(op int, _ *kmiplib.Item) []byte {
	ops := [][]byte{
		kmiplib.EncodeEnum(kmiplib.TagOperation, kmiplib.OperationCreate),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationCreateKeyPair),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationRegister),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationReKey),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OpDeriveKey),
		kmiplib.EncodeEnum(kmiplib.TagOperation, kmiplib.OperationLocate),
		kmiplib.EncodeEnum(kmiplib.TagOperation, kmiplib.OperationCheck),
		kmiplib.EncodeEnum(kmiplib.TagOperation, kmiplib.OperationGet),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationGetAttributes),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationGetAttributeList),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OpAddAttribute),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OpModifyAttribute),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OpDeleteAttribute),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OpObtainLease),
		kmiplib.EncodeEnum(kmiplib.TagOperation, kmiplib.OperationActivate),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationRevoke),
		kmiplib.EncodeEnum(kmiplib.TagOperation, kmiplib.OperationDestroy),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OpArchive),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OpRecover),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationQuery),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OpPoll),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationDiscoverVersions),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationEncrypt),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationDecrypt),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationSign),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationSignatureVerify),
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationMAC),
	}
	types := [][]byte{
		kmiplib.EncodeEnum(kmiplib.TagObjectType, kmiplib.ObjectTypeCertificate),
		kmiplib.EncodeEnum(kmiplib.TagObjectType, kmiplib.ObjectTypeSymmetricKey),
		kmiplib.EncodeEnum(kmiplib.TagObjectType, kmiplib.ObjectTypePublicKey),
		kmiplib.EncodeEnum(kmiplib.TagObjectType, kmiplib.ObjectTypePrivateKey),
	}
	return h.buildBatchItemSuccess(op, append(ops, types...)...)
}

func (h *Handler) handleDiscoverVersions(op int, _ *kmiplib.Item) []byte {
	return h.buildBatchItemSuccess(op,
		kmiplib.EncodeStructure(kmiplib.TagProtocolVersion,
			kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMajor, int32(supportedMajor)),
			kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMinor, int32(supportedMinor)),
		),
	)
}

func (h *Handler) handleEncrypt(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	dataItem := kmiplib.FindChild(payload, TagData)
	if dataItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing Data")
	}

	rec, ok := h.store.Get(uidItem.StringValue())
	if !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uidItem.StringValue()))
	}
	if reason, msg, valid := validateStateTransition(rec.State, "Encrypt"); !valid {
		return h.buildBatchItemError(op, reason, msg)
	}
	if rec.ObjectType != kmiplib.ObjectTypeSymmetricKey {
		return h.buildBatchItemError(op, ReasonInvalidField, "encrypt requires a symmetric key")
	}

	block, err := aes.NewCipher(rec.Material)
	if err != nil {
		return h.buildBatchItemError(op, ReasonCryptographicFailure, err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return h.buildBatchItemError(op, ReasonCryptographicFailure, err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ciphertext := gcm.Seal(nil, nonce, dataItem.BytesValue(), nil)

	return h.buildBatchItemSuccess(op,
		kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, rec.UID),
		kmiplib.EncodeByteString(TagData, ciphertext),
		kmiplib.EncodeByteString(TagIVCounterNonce, nonce),
	)
}

// C1 FIX: handleDecrypt validates nonce length before calling gcm.Open
func (h *Handler) handleDecrypt(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	dataItem := kmiplib.FindChild(payload, TagData)
	if dataItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing Data")
	}
	nonceItem := kmiplib.FindChild(payload, TagIVCounterNonce)
	if nonceItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing IVCounterNonce")
	}
	nonce := nonceItem.BytesValue()

	rec, ok := h.store.Get(uidItem.StringValue())
	if !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uidItem.StringValue()))
	}
	if reason, msg, valid := validateStateTransition(rec.State, "Decrypt"); !valid {
		return h.buildBatchItemError(op, reason, msg)
	}
	if rec.ObjectType != kmiplib.ObjectTypeSymmetricKey {
		return h.buildBatchItemError(op, ReasonInvalidField, "decrypt requires a symmetric key")
	}

	block, err := aes.NewCipher(rec.Material)
	if err != nil {
		return h.buildBatchItemError(op, ReasonCryptographicFailure, err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return h.buildBatchItemError(op, ReasonCryptographicFailure, err.Error())
	}

	// C1 FIX: validate nonce length to prevent panic in gcm.Open
	if len(nonce) != gcm.NonceSize() {
		return h.buildBatchItemError(op, ReasonInvalidField,
			fmt.Sprintf("invalid nonce length: got %d, expected %d", len(nonce), gcm.NonceSize()))
	}

	plaintext, err := gcm.Open(nil, nonce, dataItem.BytesValue(), nil)
	if err != nil {
		return h.buildBatchItemError(op, ReasonCryptographicFailure, fmt.Sprintf("decryption failed: %v", err))
	}
	return h.buildBatchItemSuccess(op,
		kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, rec.UID),
		kmiplib.EncodeByteString(TagData, plaintext),
	)
}

func (h *Handler) handleSign(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	dataItem := kmiplib.FindChild(payload, TagData)
	if dataItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing Data")
	}

	rec, ok := h.store.Get(uidItem.StringValue())
	if !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uidItem.StringValue()))
	}
	if reason, msg, valid := validateStateTransition(rec.State, "Sign"); !valid {
		return h.buildBatchItemError(op, reason, msg)
	}
	if rec.ObjectType != kmiplib.ObjectTypePrivateKey {
		return h.buildBatchItemError(op, ReasonInvalidField, "sign requires a private key")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(rec.Material)
	if err != nil {
		return h.buildBatchItemError(op, ReasonCryptographicFailure, err.Error())
	}
	hash := sha256.Sum256(dataItem.BytesValue())

	var signature []byte
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	case *ecdsa.PrivateKey:
		signature, err = ecdsa.SignASN1(rand.Reader, key, hash[:])
	default:
		return h.buildBatchItemError(op, ReasonCryptographicFailure, "unsupported key type")
	}
	if err != nil {
		return h.buildBatchItemError(op, ReasonCryptographicFailure, err.Error())
	}
	return h.buildBatchItemSuccess(op,
		kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, rec.UID),
		kmiplib.EncodeByteString(TagSignatureData, signature),
	)
}

func (h *Handler) handleSignatureVerify(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	dataItem := kmiplib.FindChild(payload, TagData)
	if dataItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing Data")
	}
	sigItem := kmiplib.FindChild(payload, TagSignatureData)
	if sigItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing SignatureData")
	}

	rec, ok := h.store.Get(uidItem.StringValue())
	if !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uidItem.StringValue()))
	}
	if reason, msg, valid := validateStateTransition(rec.State, "SignatureVerify"); !valid {
		return h.buildBatchItemError(op, reason, msg)
	}
	if rec.ObjectType != kmiplib.ObjectTypePublicKey {
		return h.buildBatchItemError(op, ReasonInvalidField, "verify requires a public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(rec.Material)
	if err != nil {
		return h.buildBatchItemError(op, ReasonCryptographicFailure, err.Error())
	}
	hash := sha256.Sum256(dataItem.BytesValue())

	valid := 0
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sigItem.BytesValue()) != nil {
			valid = 1
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, hash[:], sigItem.BytesValue()) {
			valid = 1
		}
	default:
		return h.buildBatchItemError(op, ReasonCryptographicFailure, "unsupported key type")
	}
	return h.buildBatchItemSuccess(op,
		kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, rec.UID),
		kmiplib.EncodeEnum(TagValidityIndicator, valid),
	)
}

func (h *Handler) handleMAC(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	dataItem := kmiplib.FindChild(payload, TagData)
	if dataItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing Data")
	}

	rec, ok := h.store.Get(uidItem.StringValue())
	if !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uidItem.StringValue()))
	}
	if reason, msg, valid := validateStateTransition(rec.State, "MAC"); !valid {
		return h.buildBatchItemError(op, reason, msg)
	}
	if rec.ObjectType != kmiplib.ObjectTypeSymmetricKey {
		return h.buildBatchItemError(op, ReasonInvalidField, "MAC requires a symmetric key")
	}

	mac := hmac.New(sha256.New, rec.Material)
	mac.Write(dataItem.BytesValue())
	return h.buildBatchItemSuccess(op,
		kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, rec.UID),
		kmiplib.EncodeByteString(TagMACData, mac.Sum(nil)),
	)
}

func (h *Handler) handleReKey(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	uid := uidItem.StringValue()
	rec, ok := h.store.Get(uid)
	if !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uid))
	}
	if reason, msg, valid := validateStateTransition(rec.State, "ReKey"); !valid {
		return h.buildBatchItemError(op, reason, msg)
	}
	rec, err := h.store.Rekey(uid)
	if err != nil {
		return h.buildBatchItemError(op, ReasonGeneralFailure, err.Error())
	}
	return h.buildBatchItemSuccess(op, kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, rec.UID))
}

func (h *Handler) handleGetAttributeList(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	uid := uidItem.StringValue()
	if _, ok := h.store.Get(uid); !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uid))
	}
	return h.buildBatchItemSuccess(op,
		kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, uid),
		kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Object Type"),
		kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Name"),
		kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Cryptographic Algorithm"),
		kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Cryptographic Length"),
		kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Cryptographic Usage Mask"),
		kmiplib.EncodeTextString(kmiplib.TagAttributeName, "State"),
	)
}

// --- Attribute operations (Add/Modify/Delete) ---

func (h *Handler) handleAddAttribute(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	attr := kmiplib.FindChild(payload, kmiplib.TagAttribute)
	if attr == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing Attribute")
	}
	nameItem := kmiplib.FindChild(attr, kmiplib.TagAttributeName)
	valueItem := kmiplib.FindChild(attr, kmiplib.TagAttributeValue)
	if nameItem == nil || valueItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing attribute name or value")
	}
	if err := h.store.SetCustomAttribute(uidItem.StringValue(), nameItem.StringValue(), valueItem.StringValue()); err != nil {
		return h.buildBatchItemError(op, ReasonGeneralFailure, err.Error())
	}
	return h.buildBatchItemSuccess(op, kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, uidItem.StringValue()))
}

func (h *Handler) handleModifyAttribute(op int, payload *kmiplib.Item) []byte {
	return h.handleAddAttribute(op, payload) // same logic: upsert
}

func (h *Handler) handleDeleteAttribute(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	attr := kmiplib.FindChild(payload, kmiplib.TagAttribute)
	if attr == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing Attribute")
	}
	nameItem := kmiplib.FindChild(attr, kmiplib.TagAttributeName)
	if nameItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing attribute name")
	}
	if err := h.store.DeleteCustomAttribute(uidItem.StringValue(), nameItem.StringValue()); err != nil {
		return h.buildBatchItemError(op, ReasonGeneralFailure, err.Error())
	}
	return h.buildBatchItemSuccess(op, kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, uidItem.StringValue()))
}

func (h *Handler) handleDeriveKey(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}

	var derivationData []byte
	if dp := kmiplib.FindChild(payload, kmiplib.TagDerivationParameters); dp != nil {
		if dd := kmiplib.FindChild(dp, kmiplib.TagDerivationData); dd != nil {
			derivationData = dd.BytesValue()
		}
	}

	name := ""
	length := int32(256)
	if tmpl := kmiplib.FindChild(payload, kmiplib.TagTemplateAttribute); tmpl != nil {
		for _, attr := range kmiplib.FindChildren(tmpl, kmiplib.TagAttribute) {
			an := kmiplib.FindChild(attr, kmiplib.TagAttributeName)
			av := kmiplib.FindChild(attr, kmiplib.TagAttributeValue)
			if an == nil || av == nil {
				continue
			}
			switch an.StringValue() {
			case "Cryptographic Length":
				length = av.IntValue()
			case "Name":
				if nv := kmiplib.FindChild(av, kmiplib.TagNameValue); nv != nil {
					name = nv.StringValue()
				}
			}
		}
	}

	rec, err := h.store.DeriveKey(uidItem.StringValue(), derivationData, name, length)
	if err != nil {
		return h.buildBatchItemError(op, ReasonGeneralFailure, err.Error())
	}
	return h.buildBatchItemSuccess(op, kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, rec.UID))
}

func (h *Handler) handleObtainLease(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	if _, ok := h.store.Get(uidItem.StringValue()); !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uidItem.StringValue()))
	}
	return h.buildBatchItemSuccess(op,
		kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, uidItem.StringValue()),
		kmiplib.EncodeInteger(kmiplib.TagLeaseTime, 3600),
	)
}

func (h *Handler) handlePoll(op int, _ *kmiplib.Item) []byte {
	return h.buildBatchItemSuccess(op)
}

func (h *Handler) handleArchive(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	uid := uidItem.StringValue()
	rec, ok := h.store.Get(uid)
	if !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uid))
	}
	if reason, msg, valid := validateStateTransition(rec.State, "Archive"); !valid {
		return h.buildBatchItemError(op, reason, msg)
	}
	if err := h.store.Archive(uid); err != nil {
		return h.buildBatchItemError(op, ReasonGeneralFailure, err.Error())
	}
	return h.buildBatchItemSuccess(op, kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, uid))
}

func (h *Handler) handleRecover(op int, payload *kmiplib.Item) []byte {
	if payload == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing request payload")
	}
	uidItem := kmiplib.FindChild(payload, kmiplib.TagUniqueIdentifier)
	if uidItem == nil {
		return h.buildBatchItemError(op, ReasonMissingData, "missing UniqueIdentifier")
	}
	uid := uidItem.StringValue()
	rec, ok := h.store.Get(uid)
	if !ok {
		return h.buildBatchItemError(op, ReasonItemNotFound, fmt.Sprintf("object not found: %s", uid))
	}
	if reason, msg, valid := validateStateTransition(rec.State, "Recover"); !valid {
		return h.buildBatchItemError(op, reason, msg)
	}
	if err := h.store.Recover(uid); err != nil {
		return h.buildBatchItemError(op, ReasonGeneralFailure, err.Error())
	}
	return h.buildBatchItemSuccess(op, kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, uid))
}

// --- Response builders ---

func (h *Handler) buildBatchItemSuccess(operation int, payloadChildren ...[]byte) []byte {
	children := [][]byte{
		kmiplib.EncodeEnum(kmiplib.TagOperation, operation),
		kmiplib.EncodeEnum(kmiplib.TagResultStatus, kmiplib.ResultStatusSuccess),
	}
	if len(payloadChildren) > 0 {
		children = append(children, kmiplib.EncodeStructure(kmiplib.TagResponsePayload, payloadChildren...))
	}
	return kmiplib.EncodeStructure(kmiplib.TagBatchItem, children...)
}

func (h *Handler) buildBatchItemError(operation, reason int, message string) []byte {
	children := [][]byte{
		kmiplib.EncodeEnum(kmiplib.TagResultStatus, kmiplib.ResultStatusOperationFailed),
		kmiplib.EncodeEnum(kmiplib.TagResultReason, reason),
		kmiplib.EncodeTextString(kmiplib.TagResultMessage, message),
	}
	if operation != 0 {
		children = append([][]byte{kmiplib.EncodeEnum(kmiplib.TagOperation, operation)}, children...)
	}
	return kmiplib.EncodeStructure(kmiplib.TagBatchItem, children...)
}

func (h *Handler) buildBatchResponse(batchCount int, batchItems [][]byte) []byte {
	parts := [][]byte{
		kmiplib.EncodeStructure(kmiplib.TagResponseHeader,
			kmiplib.EncodeStructure(kmiplib.TagProtocolVersion,
				kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMajor, int32(supportedMajor)),
				kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMinor, int32(supportedMinor)),
			),
			kmiplib.EncodeInteger(kmiplib.TagBatchCount, int32(batchCount)),
		),
	}
	parts = append(parts, batchItems...)
	return kmiplib.EncodeStructure(kmiplib.TagResponseMessage, parts...)
}

func (h *Handler) buildErrorResponse(operation, reason int, message string) []byte {
	return h.buildBatchResponse(1, [][]byte{h.buildBatchItemError(operation, reason, message)})
}
