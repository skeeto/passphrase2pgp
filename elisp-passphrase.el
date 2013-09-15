(require 'cl-lib)

(defun hash-passphrase (passphrase bits)
  (cl-loop for chunk = (secure-hash 'sha512 passphrase nil nil :binary)
           then (secure-hash 'sha512 chunk nil nil :binary)
           collect chunk into chunks
           while (> (cl-decf bits 512) 0)
           finally (cl-return (apply #'concat chunks))))

;; (cl-loop for char across (hash-passphrase "hello" 2048)
;;          collect (format "%02x" char) into chars
;;          finally (cl-return (apply #'concat chars)))
