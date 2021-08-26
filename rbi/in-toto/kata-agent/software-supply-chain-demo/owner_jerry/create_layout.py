from securesystemslib import interface
from in_toto.models.layout import Layout
from in_toto.models.metadata import Metablock

SHA256_VALUE = "91ff21380e407d373a440ea9ed5d2a1435bb8ddaff30a1e4ee671a556e66da51"

def main():
  # Load Jerry's private key to later sign the layout
  key_jerry = interface.import_rsa_privatekey_from_file("jerry")
  # Fetch and load Bob's and Alice's public keys
  # to specify that they are authorized to perform certain step in the layout
  key_alice = interface.import_rsa_publickey_from_file("../functionary_alice/alice.pub")
  key_bob = interface.import_rsa_publickey_from_file("../functionary_bob/bob.pub")
  
  layout = Layout.read({
      "_type": "layout",
      "keys": {
          key_bob["keyid"]: key_bob,
          key_alice["keyid"]: key_alice,
      },
      "steps": [{
          "name": "clone",
          "expected_materials": [],
          "expected_products": [
            ["CREATE","inclavare-containers/rbi/kata-agent/Dockerfile"],
            ["CREATE","inclavare-containers/rbi/kata-agent/kata-build-docker.sh"],
            ["CREATE","inclavare-containers/rbi/kata-agent/kata-source-code.sh"],
            ["CREATE","inclavare-containers/rbi/kata-agent/kata-test.sh"],
            ["CREATE","inclavare-containers/rbi/kata-agent/patch/Cargo.lock"],
            ["CREATE","inclavare-containers/rbi/kata-agent/patch/Makefile"],
            ["CREATE","inclavare-containers/rbi/kata-agent/patch/protocols"],
            ["CREATE","inclavare-containers/rbi/kata-agent/patch/protocols/Cargo.toml"],
            ["CREATE","inclavare-containers/rbi/kata-agent/readme.md"],
            ["CREATE","inclavare-containers/rbi/kata-agent/readme_cn.md"],
            ["CREATE","inclavare-containers/rbi/kata-agent/scripts/start.sh"],
            ["CREATE","inclavare-containers/rbi/misc/check-integrity.sh"]
          ],
          "pubkeys": [key_alice["keyid"]],
          "expected_command": [
              "git",
              "clone",
              "https://github.com/alibaba/inclavare-containers.git"
          ],
          "threshold": 1,
        },{
          "name": "build",
          "expected_materials": [
            ["MATCH", "inclavare-containers/rbi/kata-agent/Dockerfile", "WITH", "PRODUCTS", "FROM","clone"],
            ["MATCH", "inclavare-containers/rbi/kata-agent/kata-build-docker.sh", "WITH", "PRODUCTS", "FROM","clone"],
            ["MATCH", "inclavare-containers/rbi/kata-agent/kata-source-code.sh", "WITH", "PRODUCTS", "FROM","clone"],
            ["MATCH", "inclavare-containers/rbi/kata-agent/kata-test.sh", "WITH", "PRODUCTS", "FROM","clone"],
            ["MATCH", "inclavare-containers/rbi/kata-agent/patch/Cargo.lock", "WITH", "PRODUCTS", "FROM","clone"],
            ["MATCH", "inclavare-containers/rbi/kata-agent/patch/Makefile", "WITH", "PRODUCTS", "FROM","clone"],
            ["MATCH", "inclavare-containers/rbi/kata-agent/patch/protocols", "WITH", "PRODUCTS", "FROM","clone"],
            ["MATCH", "inclavare-containers/rbi/kata-agent/patch/protocols/Cargo.toml", "WITH", "PRODUCTS", "FROM","clone"],
            ["MATCH", "inclavare-containers/rbi/kata-agent/readme.md", "WITH", "PRODUCTS", "FROM","clone"],
            ["MATCH", "inclavare-containers/rbi/kata-agent/readme_cn.md", "WITH", "PRODUCTS", "FROM","clone"],
            ["MATCH", "inclavare-containers/rbi/kata-agent/scripts/start.sh", "WITH", "PRODUCTS", "FROM","clone"]
          ],
          "expected_products": [
              ["CREATE", "inclavare-containers/rbi/result/kata-agent/kata-agent"],
          ],
          "pubkeys": [key_bob["keyid"]],
          "expected_command": [
              "bash",
              "inclavare-containers/rbi/rbi.sh",
              "agent",
          ],
          "threshold": 1,
        }],
      "inspect": [{
          "name": "integrity",
          "expected_materials": [
              ["MATCH", "inclavare-containers/rbi/result/kata-agent/kata-agent", "WITH", "PRODUCTS", "FROM", "build"],
              ["MATCH", "inclavare-containers/rbi/misc/check-integrity.sh", "WITH", "PRODUCTS", "FROM", "clone"],
              # FIXME: If the routine running inspections would gather the
              # materials/products to record from the rules we wouldn't have to
              # ALLOW other files that we aren't interested in.
              ["ALLOW", "jerry.pub"],
              ["ALLOW", "root.layout"],
              ["ALLOW", ".keep"]
          ],
          "expected_products": [
              ["CREATE", "inclavare-containers/rbi/result/kata-agent/.check_done"],
              # FIXME: See expected_materials above
              ["ALLOW", "jerry.pub"],
              ["ALLOW", "root.layout"],
              ["ALLOW", ".keep"]
          ],
          "run": [
              "bash",
              "inclavare-containers/rbi/misc/check-integrity.sh",
              "inclavare-containers/rbi/result/kata-agent/kata-agent",
              SHA256_VALUE
          ]
        }],
  })

  metadata = Metablock(signed=layout)

  # Sign and dump layout to "root.layout"
  metadata.sign(key_jerry)
  metadata.dump("root.layout")

if __name__ == '__main__':
  main()
