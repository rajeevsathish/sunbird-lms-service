package controllers.assessment;

import static org.junit.Assert.assertEquals;
import static org.powermock.api.mockito.PowerMockito.when;
import static play.test.Helpers.route;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.sunbird.common.models.util.JsonKey;
import org.sunbird.common.models.util.ProjectLogger;
import org.sunbird.common.request.HeaderParam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import akka.actor.ActorRef;
import akka.actor.ActorSystem;
import akka.actor.Props;
import controllers.BaseController;
import controllers.DummyActor;
import play.libs.Json;
import play.mvc.Http.RequestBuilder;
import play.mvc.Result;
import play.test.FakeApplication;
import play.test.Helpers;
import util.RequestInterceptor;

/**
 * Created by arvind on 6/12/17.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(PowerMockRunner.class)
@PrepareForTest(RequestInterceptor.class)
@PowerMockIgnore("javax.management.*")
public class AssessmentControllerTest {

  private static FakeApplication app;
  private static Map<String,String[]> headerMap;
  private static ActorSystem system;
  private static final Props props = Props.create(DummyActor.class);


  @BeforeClass
  public static void startApp() {
    app = Helpers.fakeApplication();
    Helpers.start(app);
    headerMap = new HashMap<String, String[]>();
    headerMap.put(HeaderParam.X_Consumer_ID.getName(), new String[]{"Service test consumer"});
    headerMap.put(HeaderParam.X_Device_ID.getName(), new String[]{"Some Device Id"});
    headerMap.put(HeaderParam.X_Authenticated_Userid.getName(), new String[]{"Authenticated user id"});
    headerMap.put(JsonKey.MESSAGE_ID, new String[]{"Unique Message id"});

    system = ActorSystem.create("system");
    ActorRef subject = system.actorOf(props);
    BaseController.setActorRef(subject);
  }

  @Test
  public void testsaveAssessment() {
    PowerMockito.mockStatic(RequestInterceptor.class);
    when( RequestInterceptor.verifyRequestData(Mockito.anyObject()) ).thenReturn("{userId} uuiuhcf784508 8y8c79-fhh");
    Map<String , Object> requestMap = new HashMap<>();
    Map<String , Object> innerMap = new HashMap<>();
    innerMap.put("courseId" , "course-123");
    innerMap.put("contentId" , "content01");
    innerMap.put("attemptId" , "2");
    requestMap.put(JsonKey.REQUEST , innerMap);
    String data = mapToJson(requestMap);

    JsonNode json = Json.parse(data);
    RequestBuilder req = new RequestBuilder().bodyJson(json).uri("/v1/assessment/update").method("POST");
    req.headers(headerMap);
    Result result = route(req);
    assertEquals(200, result.status());
  }

  @Test
  public void testgetAssessment() {
    PowerMockito.mockStatic(RequestInterceptor.class);
    when( RequestInterceptor.verifyRequestData(Mockito.anyObject()) ).thenReturn("{userId} uuiuhcf784508 8y8c79-fhh");
    Map<String , Object> requestMap = new HashMap<>();
    Map<String , Object> innerMap = new HashMap<>();
    innerMap.put("courseId" , "course-123");
    requestMap.put(JsonKey.REQUEST , innerMap);
    String data = mapToJson(requestMap);

    JsonNode json = Json.parse(data);
    RequestBuilder req = new RequestBuilder().bodyJson(json).uri("/v1/assessment/result/read").method("POST");
    req.headers(headerMap);
    Result result = route(req);
    assertEquals(200, result.status());
  }


  private static String mapToJson(Map map){
    ObjectMapper mapperObj = new ObjectMapper();
    String jsonResp = "";
    try {
      jsonResp = mapperObj.writeValueAsString(map);
    } catch (IOException e) {
      ProjectLogger.log(e.getMessage(),e);
    }
    return jsonResp;
  }

}
