(ns dead-simple-jwt.handler
  (:require [compojure.core :refer :all]
            [compojure.route :as route]
            [ring.middleware.defaults :refer [wrap-defaults site-defaults]]))

(defroutes app-routes
  (GET "/" [] "You have access! This is a secret that should be accessible only with valid credentials")
  (route/not-found "Not Found"))


(defn has-valid-token
  [{auth-header "authorization"}]
  (and auth-header (.startsWith auth-header "Bearer")))

(defn wrap-authentication
  [handler]
  (fn [{headers :headers :as req}]
    (if (has-valid-token headers)
      (handler req)
      {:status 404 :body "No valid token" :headers {"Content-type" "text/plain;charset=UTF-8"}})))

(def app
  (-> app-routes
      (wrap-defaults site-defaults)
      (wrap-authentication)))
