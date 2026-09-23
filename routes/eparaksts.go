// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"encoding/json"
	"errors"

	"github.com/digimaks/api-wallet/routes/request"
	"github.com/digimaks/api-wallet/routes/response"

	"azugo.io/azugo"
	"azugo.io/core/http"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// @operationId eparakstsPrepare
// @title eparaksts prepare
// @description Method to request eparaksts signing or sealing of a file
// @accept multipart/form-data
// @param type path string true "options: `sign`, `eseal`"
// @param file file file true "File to upload. Form key needs to be the filename of the file with extension. Example: file.edoc"
// @param json formData string true "Json data for request in string format"
// @success 200 RedirectResponse response.EparakstsSignRedirectResponse "Redirect response"
// @failure 400 string string "Bad request"
// @failure 422 string string "Invalid request"
// @failure 500 string string "Internal server error"
// @resource Eparaksts
// @route /eparaksts/{type} [post].
func (r *router) eparakstsPrepare(ctx *azugo.Context) {
	// check cache if requestId key already exists
	reqJSONStr, err := ctx.Form.String("json")
	if err != nil {
		ctx.Error(err)

		return
	}

	reqJSON := &request.EparakstsSignRequest{}

	err = json.Unmarshal([]byte(reqJSONStr), reqJSON)
	if err != nil {
		ctx.Log().Error("failed to parse eparaksts sign request JSON", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:eparaksts:invalidRequestBody"))

		return
	}

	sessionID, err := r.App.SimpleSignClient().CacheGetSessionID(ctx, reqJSON.RequestID)
	if err != nil {
		ctx.Log().Error("failed to retrieve session ID from cache", zap.Error(err), zap.String("request_id", reqJSON.RequestID))
		ctx.Error(pkerrors.NewProblem("err:eparaksts:sessionLookupFailed"))

		return
	}

	if *sessionID != "" {
		ctx.Text("requestId already exists in cache")
		ctx.StatusCode(fasthttp.StatusUnprocessableEntity)

		return
	}

	reqFile, err := ctx.Form.File(reqJSON.FileName)
	if err != nil {
		ctx.Error(err)

		return
	}

	// post to prepare endpoint with formdata
	simpleSignResp, err := r.App.SimpleSignClient().Prepare(ctx, reqJSON, reqFile, ctx.Params.String("type"))
	if err != nil {
		ctx.Log().Error("failed to prepare eparaksts signing session", zap.Error(err), zap.String("type", ctx.Params.String("type")))
		ctx.Error(pkerrors.NewProblem("err:eparaksts:prepareFailed"))

		return
	}

	// save session id to cache
	err = r.App.SimpleSignClient().CacheSetSessionID(ctx, simpleSignResp.Sessions[0].RequestID, simpleSignResp.Sessions[0].SessionID)
	if err != nil {
		ctx.Log().Error("failed to store eparaksts session ID in cache", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:eparaksts:sessionCacheStoreFailed"))

		return
	}

	// send back redirectUrl
	resp := response.EparakstsSignRedirectResponse{
		RedirectURL: simpleSignResp.RedirectURL,
	}

	ctx.JSON(resp)
}

// @operationId eparakstsDownload
// @title eparaksts download
// @description Method to download signed or sealed file
// @param requestID path string true "requestId"
// @success 200 file file "File"
// @failure 400 string string "Bad request"
// @failure 422 string string "Invalid request"
// @failure 500 string string "Internal server error"
// @resource Eparaksts
// @route /eparaksts/download/{requestID} [get].
func (r *router) eparakstsDownload(ctx *azugo.Context) {
	sessionID, err := r.App.SimpleSignClient().CacheGetSessionID(ctx, ctx.Params.String("requestID"))
	if err != nil {
		ctx.Log().Error("failed to retrieve session ID from cache for download", zap.Error(err), zap.String("request_id", ctx.Params.String("requestID")))
		ctx.Error(pkerrors.NewProblem("err:eparaksts:sessionLookupFailed"))

		return
	}

	if *sessionID == "" {
		ctx.Error(http.NotFoundError{Resource: "session"})

		return
	}

	fileBytes, contentType, contentDisposition, err := r.App.SimpleSignClient().GetFile(ctx, *sessionID)
	if err != nil {
		ctx.Log().Error("failed to download signed file from eparaksts", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:eparaksts:fileDownloadFailed"))

		return
	}

	ctx.ContentType(contentType)
	ctx.Header.Add(fasthttp.HeaderContentDisposition, contentDisposition)
	ctx.Raw(fileBytes)
}

// @operationId eparakstsCloseSession
// @title eparaksts close session
// @description Method to close eparaksts session
// @param type path string true "options: `sign`, `eseal`"
// @param requestID path string true "requestId"
// @success 204 {empty} "No content"
// @failure 400 string string "Bad request"
// @failure 422 string string "Invalid request"
// @failure 500 string string "Internal server error"
// @resource Eparaksts
// @route /eparaksts/{type}/{requestID} [delete].
func (r *router) eparakstsCloseSession(ctx *azugo.Context) {
	sessionID, err := r.App.SimpleSignClient().CacheGetSessionID(ctx, ctx.Params.String("requestID"))
	if err != nil {
		ctx.Log().Error("failed to retrieve session ID from cache for close", zap.Error(err), zap.String("request_id", ctx.Params.String("requestID")))
		ctx.Error(pkerrors.NewProblem("err:eparaksts:sessionLookupFailed"))

		return
	}

	err = r.App.SimpleSignClient().CloseSession(ctx, *sessionID)
	if err != nil {
		ctx.Log().Error("failed to close eparaksts session", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:eparaksts:sessionCloseFailed"))

		return
	}

	err = r.App.SimpleSignClient().CacheDeleteSessionID(ctx, ctx.Params.String("requestID"))
	if err != nil {
		ctx.Log().Error("failed to delete session ID from cache", zap.Error(err), zap.String("request_id", ctx.Params.String("requestID")))
		ctx.Error(pkerrors.NewProblem("err:eparaksts:sessionCacheDeleteFailed"))

		return
	}

	ctx.StatusCode(fasthttp.StatusNoContent)
}

// @operationId eparakstsValidate
// @title eparaksts validate
// @description Method to validate eparaksts file
// @accept multipart/form-data
// @param file file file true "File to upload. Form key needs to be the filename of the file with extension. Example: file.edoc"
// @param json formData string true "Json data for request in string format"
// @success 200 ValidateResponse response.EparakstsValidateResponse "Validate response"
// @failure 400 string string "Bad request"
// @failure 422 string string "Invalid request"
// @failure 500 string string "Internal server error"
// @resource Eparaksts
// @route /eparaksts/validate [post].
func (r *router) eparakstsValidate(ctx *azugo.Context) {
	reqJSONStr, err := ctx.Form.String("json")
	if err != nil {
		ctx.Error(err)

		return
	}

	reqJSON := &request.ValidateRequest{}

	err = json.Unmarshal([]byte(reqJSONStr), reqJSON)
	if err != nil {
		ctx.Error(azugo.BadRequestError{Description: "invalid json"})

		return
	}

	if len(reqJSON.Files) == 0 {
		ctx.Error(azugo.BadRequestError{Description: "no file names provided"})

		return
	}

	reqFile, err := ctx.Form.File(reqJSON.Files[0].FileName)
	if err != nil {
		ctx.Error(err)

		return
	}

	simpleSignResp, err := r.App.SimpleSignClient().ValidateFile(ctx, reqJSON, reqFile)
	if err != nil {
		d := azugo.BadRequestError{}
		if errors.As(err, &d) {
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.Text(d.Description)

			return
		}

		ctx.Log().Error("failed to validate eparaksts file", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:eparaksts:validateFailed"))

		return
	}

	ctx.Raw(simpleSignResp)
}

// @operationId eparakstsIdentities
// @title eparaksts identities
// @description Method to get eparaksts identities
// @param redirecturl query string false "Redirect url"
// @success 200 RedirectResponse response.EparakstsSignRedirectResponse "Redirect response"
// @failure 400 string string "Bad request"
// @failure 422 string string "Invalid request"
// @failure 500 string string "Internal server error"
// @resource Eparaksts
// @route /eparaksts/identities [get].
func (r *router) eparakstsIdentities(ctx *azugo.Context) {
	redirectURL := ctx.Query.StringOptional("redirecturl")
	crossDevice := ctx.Query.StringOptional("crossdevice")

	resp, err := r.App.SimpleSignClient().GetIdentitiesRedirect(redirectURL, crossDevice)
	if err != nil {
		ctx.Log().Error("failed to get eparaksts identities redirect URL", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:eparaksts:identitiesRedirectFailed"))

		return
	}

	ctx.JSON(resp)
}

// @operationId eparakstsIdentitiesUlid
// @title eparaksts identities ulid
// @description Method to get eparaksts identities with ulid
// @param ulid path string true "ULID"
// @success 200 IdentitiesResponse response.EparakstsIdentitiesResponse "Identities response"
// @failure 400 string string "Bad request"
// @failure 422 string string "Invalid request"
// @failure 500 string string "Internal server error"
// @resource Eparaksts
// @route /eparaksts/identities/{id} [get].
func (r *router) eparakstsIdentitiesUlid(ctx *azugo.Context) {
	id := ctx.Params.String("id")

	resp, err := r.App.SimpleSignClient().GetIdentities(ctx, id)
	if err != nil {
		ctx.Log().Error("failed to get eparaksts identities", zap.Error(err), zap.String("id", id))
		ctx.Error(pkerrors.NewProblem("err:eparaksts:identitiesLookupFailed"))

		return
	}

	ctx.Raw(resp)
}
