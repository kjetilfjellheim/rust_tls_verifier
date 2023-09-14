const { invoke } = window.__TAURI__.tauri;

async function do_request() {
  var input = new Object();
  input.url = document.querySelector("#idUrl").value;
  var proxyFieldVal = document.querySelector("#idProxy").value;
  if (proxyFieldVal.length > 0) {
    input.proxy_url = proxyFieldVal;
  }
  input.keystore_path = document.querySelector("#idPrivateKeystorePath").value;
  input.keystore_password = document.querySelector("#idPrivateKeystorePassword").value;
  input.public_certificate_path = document.querySelector("#idPPublicCertificatePath").value;
  input.check_hostname = document.querySelector("#idCheckHostname").checked;
  input.use_inbuilt_root_certs = document.querySelector("#idUseInbuildRootCerts").checked;
  input.https_only = document.querySelector("#idHttpsOnly").checked;
  input.use_tls_sni = document.querySelector("#idUseTlsSni").checked;

  await invoke("do_request", { "input": input })
    .then((response) => {
      const val = response instanceof ArrayBuffer ? new TextDecoder().decode(response) : response
      document.querySelector("#logdata").innerText = response.logdata;
    })
    .catch((error) => {
      document.querySelector("#logdata").innerText = error.message;
    });
}
