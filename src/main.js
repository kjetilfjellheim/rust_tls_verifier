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
  input.use_https_only = document.querySelector("#idHttpsOnly").checked;
  input.use_tls_sni = document.querySelector("#idUseTlsSni").checked;

  await invoke("do_request", { "input": input })
    .then((response) => {
      if (response.success) {
        document.querySelector("#status").classList ="badge bg-success";
        document.querySelector("#status").innerText = "Success";
        document.querySelector("#error").innerText = "";
        document.querySelector("#logdata").innerText = "";
      } else {
        document.querySelector("#status").classList ="badge bg-danger";
        document.querySelector("#status").innerText = "Failed";
        document.querySelector("#error").innerText = response.error;
        document.querySelector("#logdata").innerText = response.logdata;
      }
    })
    .catch((error) => {
      document.querySelector("#status").classList ="badge bg-danger";
      document.querySelector("#status").innerText = "Failed";
      document.querySelector("#error").innerText = error.error;
      document.querySelector("#logdata").innerText = error.logdata;
    });
}
