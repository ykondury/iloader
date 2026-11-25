import { useEffect, useRef, useState } from "react";
import "./AppleID.css";
import { invoke } from "@tauri-apps/api/core";
import { emit, listen } from "@tauri-apps/api/event";
import { load } from "@tauri-apps/plugin-store";
import { Modal } from "./components/Modal";
import { toast } from "sonner";
import { useStore } from "./StoreContext";
import { useError } from "./ErrorContext";
import { Certificate } from "./pages/Certificates";
import { useTranslation } from "react-i18next";
import { createLoginRunner, pendingSubscription } from "./loginFlow";

const storePromise = load("data.json");
const runLogin = createLoginRunner();

type VerificationRequest = {
  requestId: string;
  params: { lastError: string | null };
};

export const AppleID = ({
  loggedInAs,
  setLoggedInAs,
  noKeyringAvailable,
}: {
  loggedInAs: string | null;
  setLoggedInAs: (id: string | null) => void;
  noKeyringAvailable: boolean;
}) => {
  const { t } = useTranslation();
  const [storedIds, setStoredIds] = useState<string[]>([]);
  const [forceUpdateIds, setForceUpdateIds] = useState<number>(0);
  const [emailInput, setEmailInput] = useState<string>("");
  const [passwordInput, setPasswordInput] = useState<string>("");
  const [saveCredentials, setSaveCredentials] = useState<boolean>(true);
  const [verification, setVerification] = useState<VerificationRequest | null>(null);
  const [tfaCode, setTfaCode] = useState<string>("");
  const [isLoggingIn, setIsLoggingIn] = useState(true);
  const [submittingCode, setSubmittingCode] = useState(false);
  const codePending = useRef(false);
  const listenersReady = useRef<Promise<void>>(Promise.resolve());
  const restoration = useRef<Promise<string | null> | null>(null);
  const [addAccountOpen, setAddAccountOpen] = useState<boolean>(false);
  const [anisetteServer] = useStore<string>(
    "anisetteServer3-1",
    "mac-ani.jkcoxson.com",
  );
  const [certs, setCerts] = useState<Certificate[] | null>(null);
  const [selectedSerials, setSelectedSerials] = useState<string[]>([]);
  const [chooseCertsOpen, setChooseCertsOpen] = useState<boolean>(false);
  const { err } = useError();

  useEffect(() => {
    let getLoggedInAs = async () => {
      let account = await invoke<string | null>("logged_in_as");
      setLoggedInAs(account);
    };
    let getStoredIds = async () => {
      const store = await storePromise;
      let ids = (await store.get<string[]>("ids")) ?? [];
      setStoredIds(ids);
    };

    getLoggedInAs();
    getStoredIds();
  }, [forceUpdateIds]);

  useEffect(() => {
    setSelectedSerials(certs?.map((c) => c.serialNumber) ?? []);
  }, [certs]);

  useEffect(() => {
    const tfa = pendingSubscription(listen<VerificationRequest>("2fa-required", (event) => {
      setTfaCode("");
      setVerification(event.payload);
    }));
    const certificates = pendingSubscription(listen<Certificate[]>("max-certs-reached", (event) => {
      setCerts(event.payload);
    }));
    listenersReady.current = Promise.all([tfa.ready, certificates.ready]).then(() => {});
    // Consume registration failures here as well as before a manual login.
    listenersReady.current.catch((e) => toast.error(err(t("apple_id.login_failed"), e)));
    return () => {
      tfa.dispose();
      certificates.dispose();
    };
  }, []);

  useEffect(() => {
    let active = true;
    restoration.current ??= invoke<string | null>("restore_session", { anisetteServer });
    restoration.current.then((account) => {
      if (active) setLoggedInAs(account);
    }).catch((e) => {
      if (active) toast.error(err(t("apple_id.login_failed"), e));
    }).finally(() => {
      if (active) setIsLoggingIn(false);
    });
    return () => { active = false; };
  }, []);

  const signIn = (command: "login_new" | "login_stored", email: string, args: Record<string, unknown>) => {
    if (isLoggingIn) return;
    const promise = runLogin(async () => {
      setIsLoggingIn(true);
      try {
        await listenersReady.current;
        await invoke(command, { ...args, email, anisetteServer });
        setLoggedInAs(email.trim().toLowerCase());
        setPasswordInput("");
        setAddAccountOpen(false);
        setForceUpdateIds((v) => v + 1);
      } finally {
        setVerification(null);
        setTfaCode("");
        setIsLoggingIn(false);
      }
    });
    if (promise) toast.promise(promise, {
      loading: t("apple_id.logging_in"),
      success: t("apple_id.logged_in_success"),
      error: (e) => err(t("apple_id.login_failed"), e),
    });
  };

  return (
    <>
      <h2 style={{ marginTop: 0 }}>{t("apple_id.title")}</h2>
      <div className="credentials-container">
        {loggedInAs && (
          <div className="logged-in-as card green">
            <div className="logged-info">
              <span className="logged-label">{t("apple_id.logged_in_as")}</span>
              <span className="logged-value">{loggedInAs}</span>
            </div>
            <div className="action-row">
              <button
                type="button"
                className="action-button danger"
                disabled={isLoggingIn}
                onClick={async () => {
                  let promise = async () => {
                    await invoke("invalidate_account");
                    setForceUpdateIds((v) => v + 1);
                  };
                  toast.promise(promise, {
                    loading: t("apple_id.signing_out"),
                    error: (e) => err(t("apple_id.sign_out_failed"), e),
                    success: t("apple_id.signed_out_success"),
                  });
                }}
              >
                {t("apple_id.sign_out")}
              </button>
            </div>
          </div>
        )}
        {storedIds.length > 0 && (
          <div className="stored-ids">
            <h3 style={{ margin: 0 }}>{t("apple_id.saved_logins")}</h3>
            <div className="stored-container card">
              {storedIds.map((id) => (
                <div key={id} className="stored">
                  <div className="stored-email">{id}</div>
                  <div className="action-row">
                    {!loggedInAs && (
                      <button
                        type="button"
                        className="action-button primary"
                        disabled={isLoggingIn}
                        onClick={() => {
                          signIn("login_stored", id, {});
                        }}
                      >
                        {t("apple_id.sign_in")}
                      </button>
                    )}
                    <button
                      type="button"
                      className="action-button danger"
                      disabled={isLoggingIn}
                      onClick={async () => {
                        let promise = async () => {
                          await invoke("delete_account", { email: id });
                          setForceUpdateIds((v) => v + 1);
                        };
                        toast.promise(promise, {
                          loading: t("apple_id.deleting"),
                          error: (e) => err(t("apple_id.deletion_failed"), e),
                          success: t("apple_id.deleted_success"),
                        });
                      }}
                    >
                      {t("common.delete")}
                    </button>
                  </div>
                </div>
              ))}
              {!addAccountOpen && (
                <div
                  className="stored add-account"
                  onClick={() => {
                    if (isLoggingIn) return;
                    setAddAccountOpen(true);
                  }}
                >
                  {t("apple_id.add_account")}
                </div>
              )}
            </div>
          </div>
        )}
        {((loggedInAs === null && storedIds.length === 0) ||
          addAccountOpen) && (
          <div className="new-login">
            {storedIds.length > 0 && <h3>{t("apple_id.new_login")}</h3>}
            <form
              className="credentials"
              onSubmit={async (e) => {
                e.preventDefault();
                if (!emailInput || !passwordInput) {
                  toast.warning(t("apple_id.enter_email_password"));
                  return;
                }
                signIn("login_new", emailInput, {
                  password: passwordInput,
                  saveCredentials: saveCredentials && !noKeyringAvailable,
                });
              }}
            >
              <input
                type="text"
                placeholder={t("apple_id.email_placeholder")}
                value={emailInput}
                disabled={isLoggingIn}
                onChange={(e) => setEmailInput(e.target.value)}
              />
              <input
                type="password"
                placeholder={t("apple_id.password_placeholder")}
                value={passwordInput}
                disabled={isLoggingIn}
                onChange={(e) => setPasswordInput(e.target.value)}
              />
              {noKeyringAvailable ? (
                <p className="settings-hint credentials-warning">
                  {t("apple_id.no_keyring_available")}
                </p>
              ) : (
                <div className="save-credentials">
                  <input
                    type="checkbox"
                    id="save-credentials"
                    checked={saveCredentials}
                    disabled={isLoggingIn}
                    onChange={(e) => setSaveCredentials(e.target.checked)}
                  />
                  <label htmlFor="save-credentials">
                    {t("apple_id.save_credentials")}
                  </label>
                </div>
              )}
              <button type="submit" disabled={isLoggingIn}>{t(isLoggingIn ? "apple_id.logging_in" : "apple_id.login")}</button>
              {addAccountOpen && storedIds.length > 0 && (
                <button
                  type="button"
                  disabled={isLoggingIn}
                  onClick={() => {
                    setAddAccountOpen(false);
                  }}
                >
                  {t("common.cancel")}
                </button>
              )}
            </form>
          </div>
        )}
      </div>
      <Modal sizeFit isOpen={verification !== null} zIndex={2000}>
        <h2>{t("apple_id.two_factor_title")}</h2>
        <p>{t("apple_id.two_factor_prompt")}</p>
        {verification?.params.lastError && <p role="alert">{verification.params.lastError}</p>}
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            if (codePending.current || !verification) return;
            const code = tfaCode.trim();
            if (!/^\d{6}$/.test(code)) {
              toast.warning(t("apple_id.valid_6digit"));
              return;
            }
            const requestId = verification.requestId;
            codePending.current = true;
            setSubmittingCode(true);
            try {
              await emit(`2fa-response-${requestId}`, code);
              setVerification((current) => current?.requestId === requestId ? null : current);
              setTfaCode("");
            } catch (e) {
              toast.error(err(t("apple_id.login_failed"), { type: "misc", message: String(e) }));
            } finally {
              codePending.current = false;
              setSubmittingCode(false);
            }
          }}
        >
          <input
            type="text"
            placeholder={t("apple_id.verification_placeholder")}
            value={tfaCode}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            disabled={submittingCode}
            onChange={(e) => setTfaCode(e.target.value)}
            style={{ marginRight: "0.5em" }}
          />
          <button type="submit" disabled={submittingCode}>{t("apple_id.submit")}</button>
        </form>
      </Modal>
      <Modal sizeFit isOpen={certs !== null} zIndex={2000}>
        <h2 className="cert-header">{t("apple_id.max_certs_title")}</h2>
        <p className="certs-desc">{t("apple_id.max_certs_desc")}</p>
        <p
          className="certs-see"
          role="button"
          tabIndex={0}
          onClick={() => setChooseCertsOpen((v) => !v)}
        >
          {chooseCertsOpen
            ? t("apple_id.hide_certificate_list")
            : t("apple_id.choose_what_to_revoke")}
        </p>
        {chooseCertsOpen && certs && (
          <div className="certs-list">
            {certs.map((cert) => (
              <div
                key={cert.serialNumber}
                className="cert-item"
                onClick={() => {
                  setSelectedSerials((prev) => {
                    if (prev.includes(cert.serialNumber)) {
                      return prev.filter((s) => s !== cert.serialNumber);
                    } else {
                      return [...prev, cert.serialNumber];
                    }
                  });
                }}
              >
                <input
                  type="checkbox"
                  id={cert.serialNumber}
                  name={cert.serialNumber}
                  value={cert.serialNumber}
                  checked={selectedSerials.includes(cert.serialNumber)}
                />
                <label htmlFor={cert.serialNumber}>
                  {cert.name} - {cert.machineName}
                </label>
              </div>
            ))}
          </div>
        )}
        <div className="certs-buttons">
          <button
            className="action-button primary"
            onClick={async () => {
              await emit(
                "max-certs-response",
                selectedSerials.length > 0 ? selectedSerials : null,
              );
              setCerts(null);
              setChooseCertsOpen(false);
            }}
          >
            {t("apple_id.continue")}
          </button>
          <button
            className="action-button danger"
            onClick={async () => {
              await emit("max-certs-response", null);
              setCerts(null);
              setChooseCertsOpen(false);
            }}
          >
            {t("common.cancel")}
          </button>
        </div>
      </Modal>
    </>
  );
};
