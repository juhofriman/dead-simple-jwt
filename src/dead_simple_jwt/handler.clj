(ns dead-simple-jwt.handler
  (:require [compojure.core :refer :all]
            [compojure.route :as route]
            [ring.middleware.params :refer [wrap-params]]
            [pandect.algo.sha1 :refer [sha1-hmac]]
            [base64-clj.core :as base64]))

; Passwords are now just plain text, naturally you need to hash these normally in real scenarios
(def user-realm {"frank" "viceral"
                 "liza" "necronomicon"})

; This is the secret key used in sha1-hmac, it really should not be in code!!
(def secret-key "wfe249284093roi2j24f8i2j82hvo2824foi2fo2")

(defn generate-jwt-token
  [username]
  (let [header "{\"alg\": \"HS256\", \"typ\": \"JWT\"}"
        payload (str "{\"username\":\"" username "\"}")
        unsigned-token (str (base64/encode header) "." (base64/encode payload))]
    (str
     (base64/encode header)
     "."
     (base64/encode payload)
     "."
     (base64/encode (sha1-hmac unsigned-token secret-key)))))

(defn has-access
  [username password]
  (and (contains? user-realm username) (= (get user-realm username) password)))

(defroutes app-routes
  (POST "/authorize"
        [username password]
        (if (has-access username password)
          (generate-jwt-token username)
          {:status 403 :body "Invalid credentials"}))
  (GET "/" [] "You have access! This is a secret that should be accessible only with valid credentials")
  (route/not-found "Not Found"))

(defn has-valid-token
  [{auth-header "authorization"}]
  (and auth-header (.startsWith auth-header "Bearer")))

(defn wrap-authentication
  [handler]
  (fn [{headers :headers uri :uri :as req}]
    (if (or (= uri "/authorize") (has-valid-token headers))
      (handler req)
      {:status 403 :body "No valid token"})))

(defn wrap-content-type
  [handler content-type]
  (fn [req]
    (assoc-in (handler req) [:headers "Content-type"] content-type)))

(def app
  (-> app-routes
      (wrap-params)
      (wrap-authentication)
      (wrap-content-type "text/plain;charset=UTF-8")))
