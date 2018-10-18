/*
 * Copyright 2018 InfAI (CC SES)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package lib

import (
	"log"
	"net/http"

	"encoding/json"

	"github.com/SmartEnergyPlatform/jwt-http-router"
	"github.com/SmartEnergyPlatform/util/http/cors"
	"github.com/SmartEnergyPlatform/util/http/logger"
	"github.com/SmartEnergyPlatform/util/http/response"
)

func StartApi() {
	log.Println("start server on port: ", Config.ServerPort)
	httpHandler := getRoutes()
	corseHandler := cors.New(httpHandler)
	logger := logger.New(corseHandler, Config.LogLevel)
	log.Println(http.ListenAndServe(":"+Config.ServerPort, logger))
}

func getRoutes() (router *jwt_http_router.Router) {
	router = jwt_http_router.New(jwt_http_router.JwtConfig{
		ForceUser: Config.ForceUser == "true",
		ForceAuth: Config.ForceAuth == "true",
		PubRsa:    Config.JwtPubRsa,
	})

	router.GET("/administrate/exists/:resource_kind/:resource", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		resource := ps.ByName("resource")
		exists, err := ResourceExists(kind, resource)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(exists)
	})

	router.GET("/administrate/rights/:resource_kind", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		list, err := GetRightsToAdministrate(kind, jwt.UserId, jwt.RealmAccess.Roles)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.GET("/administrate/rights/:resource_kind/get/:resource", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		resource := ps.ByName("resource")
		if err := CheckUserOrGroup(kind, resource, jwt.UserId, jwt.RealmAccess.Roles, "a"); err != nil {
			log.Println("access denied", err)
			http.Error(res, "access denied", http.StatusUnauthorized)
			return
		}
		list, err := GetResource(kind, resource)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(list) == 0 {
			http.Error(res, "404", http.StatusNotFound)
			return
		}
		response.To(res).Json(list[0])
	})

	router.GET("/administrate/rights/:resource_kind/query/:query/:limit/:offset", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		query := ps.ByName("query")
		limit := ps.ByName("limit")
		offset := ps.ByName("offset")
		list, err := SearchRightsToAdministrate(kind, jwt.UserId, jwt.RealmAccess.Roles, query, limit, offset)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.GET("/jwt/search/:resource_kind/:query/:right", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		query := ps.ByName("query")
		list, err := SearchListAll(kind, query, jwt.UserId, jwt.RealmAccess.Roles, right)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.GET("/jwt/select/:resource_kind/:field/:value/:right", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		field := ps.ByName("field")
		value := ps.ByName("value")
		list, err := SelectByFieldAll(kind, field, value, jwt.UserId, jwt.RealmAccess.Roles, right)
		if err != nil {
			log.Println("ERROR:", err)
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.GET("/jwt/select/:resource_kind/:field/:value/:right/:limit/:offset/:orderfeature/:direction", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		field := ps.ByName("field")
		value := ps.ByName("value")
		limit := ps.ByName("limit")
		offset := ps.ByName("offset")
		orderfeature := ps.ByName("orderfeature")
		direction := ps.ByName("direction")
		list, err := SelectByFieldOrdered(kind, field, value, jwt.UserId, jwt.RealmAccess.Roles, right, limit, offset, orderfeature, direction == "asc")
		if err != nil {
			log.Println("ERROR:", err)
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.GET("/jwt/search/:resource_kind/:query/:right/:limit/:offset", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		query := ps.ByName("query")
		limit := ps.ByName("limit")
		offset := ps.ByName("offset")
		list, err := SearchList(kind, query, jwt.UserId, jwt.RealmAccess.Roles, right, limit, offset)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.GET("/jwt/search/:resource_kind/:query/:right/:limit/:offset/:orderfeature", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		query := ps.ByName("query")
		limit := ps.ByName("limit")
		offset := ps.ByName("offset")
		order := ps.ByName("orderfeature")
		list, err := SearchOrderedList(kind, query, jwt.UserId, jwt.RealmAccess.Roles, right, order, true, limit, offset)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.GET("/jwt/search/:resource_kind/:query/:right/:limit/:offset/:orderfeature/asc", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		query := ps.ByName("query")
		limit := ps.ByName("limit")
		offset := ps.ByName("offset")
		order := ps.ByName("orderfeature")
		list, err := SearchOrderedList(kind, query, jwt.UserId, jwt.RealmAccess.Roles, right, order, true, limit, offset)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.GET("/jwt/search/:resource_kind/:query/:right/:limit/:offset/:orderfeature/desc", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		query := ps.ByName("query")
		limit := ps.ByName("limit")
		offset := ps.ByName("offset")
		order := ps.ByName("orderfeature")
		list, err := SearchOrderedList(kind, query, jwt.UserId, jwt.RealmAccess.Roles, right, order, false, limit, offset)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	//TODO: add limit/offset variant
	router.GET("/jwt/list/:resource_kind/:right", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		list, err := GetFullListForUserOrGroup(kind, jwt.UserId, jwt.RealmAccess.Roles, right)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.GET("/jwt/list/:resource_kind/:right/:limit/:offset", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		limit := ps.ByName("limit")
		offset := ps.ByName("offset")
		list, err := GetListForUserOrGroup(kind, jwt.UserId, jwt.RealmAccess.Roles, right, limit, offset)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.GET("/jwt/list/:resource_kind/:right/:limit/:offset/:orderfeature/asc", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		limit := ps.ByName("limit")
		offset := ps.ByName("offset")
		orderfeature := ps.ByName("orderfeature")
		list, err := GetOrderedListForUserOrGroup(kind, jwt.UserId, jwt.RealmAccess.Roles, right, limit, offset, orderfeature, true)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.GET("/jwt/list/:resource_kind/:right/:limit/:offset/:orderfeature/desc", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		limit := ps.ByName("limit")
		offset := ps.ByName("offset")
		orderfeature := ps.ByName("orderfeature")
		list, err := GetOrderedListForUserOrGroup(kind, jwt.UserId, jwt.RealmAccess.Roles, right, limit, offset, orderfeature, false)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.GET("/jwt/check/:resource_kind/:resource_id/:right", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		resource := ps.ByName("resource_id")
		err := CheckUserOrGroup(kind, resource, jwt.UserId, jwt.RealmAccess.Roles, right)
		if err != nil {
			log.Println("access denied", err)
			http.Error(res, "access denied: "+err.Error(), http.StatusUnauthorized)
			return
		}
		ok := map[string]string{"status": "ok"}
		response.To(res).Json(ok)
	})

	router.GET("/jwt/check/:resource_kind/:resource_id/:right/bool", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		resource := ps.ByName("resource_id")
		err := CheckUserOrGroup(kind, resource, jwt.UserId, jwt.RealmAccess.Roles, right)
		if err != nil {
			response.To(res).Json(false)
		} else {
			response.To(res).Json(true)
		}
	})

	router.POST("/ids/check/:resource_kind/:right", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		ids := []string{}
		err := json.NewDecoder(r.Body).Decode(&ids)
		if err != nil {
			log.Println("WARNING: error in user send data", err)
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		ok, err := CheckListUserOrGroup(kind, ids, jwt.UserId, jwt.RealmAccess.Roles, right)
		if err != nil {
			log.Println("ERROR:", ids, err)
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(ok)
	})

	router.POST("/ids/select/:resource_kind/:right", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		ids := []string{}
		err := json.NewDecoder(r.Body).Decode(&ids)
		if err != nil {
			log.Println("WARNING: error in user send data", err)
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		result, err := GetListFromIds(kind, ids, jwt.UserId, jwt.RealmAccess.Roles, right)
		if err != nil {
			log.Println("ERROR:", ids, err)
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(result)
	})

	router.POST("/ids/select/:resource_kind/:right/:limit/:offset/:orderfeature/:direction", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		limit := ps.ByName("limit")
		offset := ps.ByName("offset")
		orderfeature := ps.ByName("orderfeature")
		direction := ps.ByName("direction")
		ids := []string{}
		err := json.NewDecoder(r.Body).Decode(&ids)
		if err != nil {
			log.Println("WARNING: error in user send data", err)
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		result, err := GetListFromIdsOrdered(kind, ids, jwt.UserId, jwt.RealmAccess.Roles, right, limit, offset, orderfeature, direction == "asc")
		if err != nil {
			log.Println("ERROR:", ids, err)
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(result)
	})

	router.GET("/user/list/:user/:resource_kind/:right", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		user := ps.ByName("user")
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		list, err := GetListForUser(kind, user, right)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.GET("/user/check/:user/:resource_kind/:resource_id/:right", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		user := ps.ByName("user")
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		resource := ps.ByName("resource_id")
		err := CheckUser(kind, resource, user, right)
		if err != nil {
			log.Println("access denied", err)
			http.Error(res, "access denied", http.StatusUnauthorized)
			return
		}
		ok := map[string]string{"status": "ok"}
		response.To(res).Json(ok)
	})

	router.GET("/group/list/:group/:resource_kind/:right", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		group := ps.ByName("group")
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		list, err := GetListForGroup(kind, []string{group}, right)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.GET("/group/check/:group/:resource_kind/:resource_id/:right", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		group := ps.ByName("group")
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		resource := ps.ByName("resource_id")
		err := CheckGroups(kind, resource, []string{group}, right)
		if err != nil {
			log.Println("access denied", err)
			http.Error(res, "access denied", http.StatusUnauthorized)
			return
		}
		ok := map[string]string{"status": "ok"}
		response.To(res).Json(ok)
	})

	router.GET("/export", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		exports, err := Export()
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(exports)
	})

	router.PUT("/import", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		imports := map[string][]ResourceRights{}
		err := json.NewDecoder(r.Body).Decode(&imports)
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		err = Import(imports)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		ok := map[string]string{"status": "ok"}
		response.To(res).Json(ok)
	})

	router.POST("/jwt/search/:resource_kind/:query/:right/:limit/:offset/:orderfeature/asc", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		query := ps.ByName("query")
		limit := ps.ByName("limit")
		offset := ps.ByName("offset")
		order := ps.ByName("orderfeature")
		selection := Selection{}
		err := json.NewDecoder(r.Body).Decode(&selection)
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		selectionFilter, err := selection.GetFilter(jwt)
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		list, err := SearchOrderedListWithSelection(kind, query, jwt.UserId, jwt.RealmAccess.Roles, right, order, true, limit, offset, selectionFilter)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.POST("/jwt/search/:resource_kind/:query/:right/:limit/:offset/:orderfeature/desc", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		query := ps.ByName("query")
		limit := ps.ByName("limit")
		offset := ps.ByName("offset")
		order := ps.ByName("orderfeature")
		selection := Selection{}
		err := json.NewDecoder(r.Body).Decode(&selection)
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		selectionFilter, err := selection.GetFilter(jwt)
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		list, err := SearchOrderedListWithSelection(kind, query, jwt.UserId, jwt.RealmAccess.Roles, right, order, false, limit, offset, selectionFilter)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.POST("/jwt/list/:resource_kind/:right/:limit/:offset/:orderfeature/asc", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		limit := ps.ByName("limit")
		offset := ps.ByName("offset")
		orderfeature := ps.ByName("orderfeature")
		selection := Selection{}
		err := json.NewDecoder(r.Body).Decode(&selection)
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		selectionFilter, err := selection.GetFilter(jwt)
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		list, err := GetOrderedListForUserOrGroupWithSelection(kind, jwt.UserId, jwt.RealmAccess.Roles, right, limit, offset, orderfeature, true, selectionFilter)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	router.POST("/jwt/list/:resource_kind/:right/:limit/:offset/:orderfeature/desc", func(res http.ResponseWriter, r *http.Request, ps jwt_http_router.Params, jwt jwt_http_router.Jwt) {
		kind := ps.ByName("resource_kind")
		right := ps.ByName("right")
		limit := ps.ByName("limit")
		offset := ps.ByName("offset")
		orderfeature := ps.ByName("orderfeature")
		selection := Selection{}
		err := json.NewDecoder(r.Body).Decode(&selection)
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		selectionFilter, err := selection.GetFilter(jwt)
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		list, err := GetOrderedListForUserOrGroupWithSelection(kind, jwt.UserId, jwt.RealmAccess.Roles, right, limit, offset, orderfeature, false, selectionFilter)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		response.To(res).Json(list)
	})

	return
}
