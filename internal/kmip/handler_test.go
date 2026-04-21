package kmip

import (
	"testing"

	kmiplib "github.com/cyphera-labs/kmip-go"
	"github.com/cyphera-labs/open-kmip-server/internal/storage"
)

func newTestHandler() *Handler {
	store := storage.NewMemoryStore()
	return NewHandler(store, nil, nil)
}

func mustCreateKey(t *testing.T, h *Handler) string {
	t.Helper()
	// Build a Create request for AES-256
	payload := kmiplib.EncodeStructure(kmiplib.TagRequestPayload,
		kmiplib.EncodeEnum(kmiplib.TagObjectType, kmiplib.ObjectTypeSymmetricKey),
		kmiplib.EncodeStructure(kmiplib.TagTemplateAttribute,
			kmiplib.EncodeStructure(kmiplib.TagAttribute,
				kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Cryptographic Algorithm"),
				kmiplib.EncodeEnum(kmiplib.TagAttributeValue, kmiplib.AlgorithmAES),
			),
			kmiplib.EncodeStructure(kmiplib.TagAttribute,
				kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Cryptographic Length"),
				kmiplib.EncodeInteger(kmiplib.TagAttributeValue, 256),
			),
			kmiplib.EncodeStructure(kmiplib.TagAttribute,
				kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Cryptographic Usage Mask"),
				kmiplib.EncodeInteger(kmiplib.TagAttributeValue, int32(kmiplib.UsageMaskEncrypt|kmiplib.UsageMaskDecrypt)),
			),
			kmiplib.EncodeStructure(kmiplib.TagAttribute,
				kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Name"),
				kmiplib.EncodeStructure(kmiplib.TagAttributeValue,
					kmiplib.EncodeTextString(kmiplib.TagNameValue, "test-key"),
					kmiplib.EncodeEnum(kmiplib.TagNameType, kmiplib.NameTypeUninterpretedTextString),
				),
			),
		),
	)

	batchItem := kmiplib.EncodeStructure(kmiplib.TagBatchItem,
		kmiplib.EncodeEnum(kmiplib.TagOperation, kmiplib.OperationCreate),
		payload,
	)

	req := kmiplib.EncodeStructure(kmiplib.TagRequestMessage,
		kmiplib.EncodeStructure(kmiplib.TagRequestHeader,
			kmiplib.EncodeStructure(kmiplib.TagProtocolVersion,
				kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMajor, 1),
				kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMinor, 4),
			),
			kmiplib.EncodeInteger(kmiplib.TagBatchCount, 1),
		),
		batchItem,
	)

	resp := h.HandleRequest(req, "test", "127.0.0.1", "conn-1")
	msg, err := kmiplib.DecodeTTLV(resp, 0)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}

	bi := kmiplib.FindChild(msg, kmiplib.TagBatchItem)
	status := kmiplib.FindChild(bi, kmiplib.TagResultStatus)
	if status == nil || int(status.IntValue()) != kmiplib.ResultStatusSuccess {
		rm := kmiplib.FindChild(bi, kmiplib.TagResultMessage)
		msg := ""
		if rm != nil {
			msg = rm.StringValue()
		}
		t.Fatalf("Create failed: %s", msg)
	}

	rp := kmiplib.FindChild(bi, kmiplib.TagResponsePayload)
	uid := kmiplib.FindChild(rp, kmiplib.TagUniqueIdentifier)
	if uid == nil {
		t.Fatal("no UID in create response")
	}
	return uid.StringValue()
}

func sendUIDOp(h *Handler, operation int, uid string) (*kmiplib.Item, error) {
	payload := kmiplib.EncodeStructure(kmiplib.TagRequestPayload,
		kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, uid),
	)
	batchItem := kmiplib.EncodeStructure(kmiplib.TagBatchItem,
		kmiplib.EncodeEnum(kmiplib.TagOperation, operation),
		payload,
	)
	req := kmiplib.EncodeStructure(kmiplib.TagRequestMessage,
		kmiplib.EncodeStructure(kmiplib.TagRequestHeader,
			kmiplib.EncodeStructure(kmiplib.TagProtocolVersion,
				kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMajor, 1),
				kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMinor, 4),
			),
			kmiplib.EncodeInteger(kmiplib.TagBatchCount, 1),
		),
		batchItem,
	)

	resp := h.HandleRequest(req, "test", "127.0.0.1", "conn-1")
	msg, err := kmiplib.DecodeTTLV(resp, 0)
	if err != nil {
		return nil, err
	}
	return kmiplib.FindChild(msg, kmiplib.TagBatchItem), nil
}

func getStatus(bi *kmiplib.Item) int {
	s := kmiplib.FindChild(bi, kmiplib.TagResultStatus)
	if s == nil {
		return -1
	}
	return int(s.IntValue())
}

// --- Tests ---

func TestCreate(t *testing.T) {
	h := newTestHandler()
	uid := mustCreateKey(t, h)
	if uid == "" {
		t.Error("empty UID")
	}
}

func TestGetAfterCreate(t *testing.T) {
	h := newTestHandler()
	uid := mustCreateKey(t, h)

	bi, err := sendUIDOp(h, kmiplib.OperationGet, uid)
	if err != nil {
		t.Fatal(err)
	}
	if getStatus(bi) != kmiplib.ResultStatusSuccess {
		t.Error("Get failed")
	}

	rp := kmiplib.FindChild(bi, kmiplib.TagResponsePayload)
	retUID := kmiplib.FindChild(rp, kmiplib.TagUniqueIdentifier)
	if retUID == nil || retUID.StringValue() != uid {
		t.Error("UID mismatch in Get response")
	}
}

func TestActivateAndDestroy(t *testing.T) {
	h := newTestHandler()
	uid := mustCreateKey(t, h)

	// Activate
	bi, _ := sendUIDOp(h, kmiplib.OperationActivate, uid)
	if getStatus(bi) != kmiplib.ResultStatusSuccess {
		t.Error("Activate failed")
	}

	// Destroy
	bi, _ = sendUIDOp(h, kmiplib.OperationDestroy, uid)
	if getStatus(bi) != kmiplib.ResultStatusSuccess {
		t.Error("Destroy failed")
	}

	// Get after destroy should fail
	bi, _ = sendUIDOp(h, kmiplib.OperationGet, uid)
	if getStatus(bi) == kmiplib.ResultStatusSuccess {
		t.Error("Get should fail after Destroy")
	}
}

func TestLocate(t *testing.T) {
	h := newTestHandler()
	mustCreateKey(t, h)

	// Build Locate request
	payload := kmiplib.EncodeStructure(kmiplib.TagRequestPayload,
		kmiplib.EncodeStructure(kmiplib.TagAttribute,
			kmiplib.EncodeTextString(kmiplib.TagAttributeName, "Name"),
			kmiplib.EncodeStructure(kmiplib.TagAttributeValue,
				kmiplib.EncodeTextString(kmiplib.TagNameValue, "test-key"),
				kmiplib.EncodeEnum(kmiplib.TagNameType, kmiplib.NameTypeUninterpretedTextString),
			),
		),
	)
	batchItem := kmiplib.EncodeStructure(kmiplib.TagBatchItem,
		kmiplib.EncodeEnum(kmiplib.TagOperation, kmiplib.OperationLocate),
		payload,
	)
	req := kmiplib.EncodeStructure(kmiplib.TagRequestMessage,
		kmiplib.EncodeStructure(kmiplib.TagRequestHeader,
			kmiplib.EncodeStructure(kmiplib.TagProtocolVersion,
				kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMajor, 1),
				kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMinor, 4),
			),
			kmiplib.EncodeInteger(kmiplib.TagBatchCount, 1),
		),
		batchItem,
	)

	resp := h.HandleRequest(req, "test", "127.0.0.1", "conn-1")
	msg, _ := kmiplib.DecodeTTLV(resp, 0)
	bi := kmiplib.FindChild(msg, kmiplib.TagBatchItem)
	if getStatus(bi) != kmiplib.ResultStatusSuccess {
		t.Error("Locate failed")
	}

	rp := kmiplib.FindChild(bi, kmiplib.TagResponsePayload)
	uids := kmiplib.FindChildren(rp, kmiplib.TagUniqueIdentifier)
	if len(uids) == 0 {
		t.Error("Locate returned no UIDs")
	}
}

func TestStateMachine_EncryptRequiresActive(t *testing.T) {
	h := newTestHandler()
	uid := mustCreateKey(t, h) // pre-active

	// Try encrypt on pre-active key — should fail
	payload := kmiplib.EncodeStructure(kmiplib.TagRequestPayload,
		kmiplib.EncodeTextString(kmiplib.TagUniqueIdentifier, uid),
		kmiplib.EncodeByteString(TagData, []byte("hello")),
	)
	batchItem := kmiplib.EncodeStructure(kmiplib.TagBatchItem,
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationEncrypt),
		payload,
	)
	req := kmiplib.EncodeStructure(kmiplib.TagRequestMessage,
		kmiplib.EncodeStructure(kmiplib.TagRequestHeader,
			kmiplib.EncodeStructure(kmiplib.TagProtocolVersion,
				kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMajor, 1),
				kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMinor, 4),
			),
			kmiplib.EncodeInteger(kmiplib.TagBatchCount, 1),
		),
		batchItem,
	)

	resp := h.HandleRequest(req, "test", "127.0.0.1", "conn-1")
	msg, _ := kmiplib.DecodeTTLV(resp, 0)
	bi := kmiplib.FindChild(msg, kmiplib.TagBatchItem)
	if getStatus(bi) == kmiplib.ResultStatusSuccess {
		t.Error("Encrypt should fail on pre-active key")
	}
}

func TestQuery(t *testing.T) {
	h := newTestHandler()

	payload := kmiplib.EncodeStructure(kmiplib.TagRequestPayload)
	batchItem := kmiplib.EncodeStructure(kmiplib.TagBatchItem,
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationQuery),
		payload,
	)
	req := kmiplib.EncodeStructure(kmiplib.TagRequestMessage,
		kmiplib.EncodeStructure(kmiplib.TagRequestHeader,
			kmiplib.EncodeStructure(kmiplib.TagProtocolVersion,
				kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMajor, 1),
				kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMinor, 4),
			),
			kmiplib.EncodeInteger(kmiplib.TagBatchCount, 1),
		),
		batchItem,
	)

	resp := h.HandleRequest(req, "test", "127.0.0.1", "conn-1")
	msg, _ := kmiplib.DecodeTTLV(resp, 0)
	bi := kmiplib.FindChild(msg, kmiplib.TagBatchItem)
	if getStatus(bi) != kmiplib.ResultStatusSuccess {
		t.Error("Query failed")
	}

	rp := kmiplib.FindChild(bi, kmiplib.TagResponsePayload)
	ops := kmiplib.FindChildren(rp, kmiplib.TagOperation)
	if len(ops) < 10 {
		t.Errorf("Query returned %d operations, expected 10+", len(ops))
	}
}

func TestGetNonexistent(t *testing.T) {
	h := newTestHandler()

	bi, _ := sendUIDOp(h, kmiplib.OperationGet, "does-not-exist")
	if getStatus(bi) == kmiplib.ResultStatusSuccess {
		t.Error("Get should fail for nonexistent UID")
	}
}

func TestDiscoverVersions(t *testing.T) {
	h := newTestHandler()

	payload := kmiplib.EncodeStructure(kmiplib.TagRequestPayload)
	batchItem := kmiplib.EncodeStructure(kmiplib.TagBatchItem,
		kmiplib.EncodeEnum(kmiplib.TagOperation, OperationDiscoverVersions),
		payload,
	)
	req := kmiplib.EncodeStructure(kmiplib.TagRequestMessage,
		kmiplib.EncodeStructure(kmiplib.TagRequestHeader,
			kmiplib.EncodeStructure(kmiplib.TagProtocolVersion,
				kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMajor, 1),
				kmiplib.EncodeInteger(kmiplib.TagProtocolVersionMinor, 4),
			),
			kmiplib.EncodeInteger(kmiplib.TagBatchCount, 1),
		),
		batchItem,
	)

	resp := h.HandleRequest(req, "test", "127.0.0.1", "conn-1")
	msg, _ := kmiplib.DecodeTTLV(resp, 0)
	bi := kmiplib.FindChild(msg, kmiplib.TagBatchItem)
	if getStatus(bi) != kmiplib.ResultStatusSuccess {
		t.Error("DiscoverVersions failed")
	}
}

func TestCheck(t *testing.T) {
	h := newTestHandler()
	uid := mustCreateKey(t, h)

	bi, _ := sendUIDOp(h, kmiplib.OperationCheck, uid)
	if getStatus(bi) != kmiplib.ResultStatusSuccess {
		t.Error("Check failed")
	}
}
