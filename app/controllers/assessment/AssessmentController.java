/**
 * 
 */
package controllers.assessment;

import java.util.HashMap;
import java.util.concurrent.TimeUnit;

import org.sunbird.common.models.util.ActorOperations;
import org.sunbird.common.models.util.JsonKey;
import org.sunbird.common.models.util.LogHelper;
import org.sunbird.common.request.ExecutionContext;
import org.sunbird.common.request.HeaderParam;
import org.sunbird.common.request.Request;
import org.sunbird.common.request.RequestValidator;

import com.fasterxml.jackson.databind.JsonNode;

import akka.util.Timeout;
import controllers.BaseController;
import play.libs.F.Promise;
import play.mvc.Result;

/**
 * This controller will handle all the api
 * related to Assessment
 * @author Manzarul
 */
public class AssessmentController  extends BaseController{
	
private LogHelper logger = LogHelper.getInstance(AssessmentController.class.getName());
	
	/**
	 * This method will add assessment entry into cassandra db.
	 * @return Promise<Result>
	 */
	public Promise<Result> saveAssessment() {
		try {
			JsonNode requestData = request().body().asJson();
			logger.info("add new assessment data=" + requestData);
			Request reqObj = (Request) mapper.RequestMapper.mapRequest(requestData, Request.class);
			RequestValidator.validateSaveAssessment(reqObj);
			reqObj.setOperation(ActorOperations.SAVE_ASSESSMENT.getValue());
	        reqObj.setRequest_id(ExecutionContext.getRequestId());
	        reqObj.setEnv(getEnvironment());
			HashMap<String, Object> innerMap = new HashMap<>();
			innerMap.put(JsonKey.ASSESSMENT, reqObj.getRequest());
			innerMap.put(JsonKey.REQUESTED_BY,getUserIdByAuthToken(request().getHeader(HeaderParam.X_Authenticated_Userid.getName())));
			reqObj.setRequest(innerMap);
			Timeout timeout = new Timeout(Akka_wait_time, TimeUnit.SECONDS);
			Promise<Result> res = actorResponseHandler(getRemoteActor(),reqObj,timeout,null);
			return res;
		} catch (Exception e) {
			return Promise.<Result> pure(createCommonExceptionResponse(e));
		}
	}
     
	/**
	 * This method will provide user assessment details based on userid and course id.
	 * if only course id is coming then it will provide all the user assessment for that course.
	 * if course id and user id's both coming then it will provide only those users assessment for that 
	 * course. 
	 * @return Promise<Result>
	 */
	public Promise<Result> getAssessment() {
		try {
			JsonNode requestData = request().body().asJson();
			logger.info("get assessment request=" + requestData);
			Request reqObj = (Request) mapper.RequestMapper.mapRequest(requestData, Request.class);
			RequestValidator.validateGetAssessment(reqObj);
			reqObj.setOperation(ActorOperations.GET_ASSESSMENT.getValue());
	        reqObj.setRequest_id(ExecutionContext.getRequestId());
	        reqObj.setEnv(getEnvironment());
			HashMap<String, Object> innerMap = new HashMap<>();
			innerMap.put(JsonKey.ASSESSMENT, reqObj.getRequest());
			innerMap.put(JsonKey.REQUESTED_BY,getUserIdByAuthToken(request().getHeader(HeaderParam.X_Authenticated_Userid.getName())));
			reqObj.setRequest(innerMap);
			Timeout timeout = new Timeout(Akka_wait_time, TimeUnit.SECONDS);
			Promise<Result> res = actorResponseHandler(getRemoteActor(),reqObj,timeout,null);
			return res;
		} catch (Exception e) {
			return Promise.<Result> pure(createCommonExceptionResponse(e));
		}
	}

	
}