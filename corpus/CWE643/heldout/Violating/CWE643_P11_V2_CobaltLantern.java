import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_CobaltLantern {

    public void runCobaltLantern() throws XPathExpressionException {
        String data;
        if (true) {
            data = System.getenv("COBALT_LANTERN_ADD");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_CobaltLanternSink()).sinkCobaltLantern(dataHashMap);
    }
}

class CWE643_P11_V2_CobaltLanternSink {

    public void sinkCobaltLantern(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String cobaltLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            cobaltLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            cobaltLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] cobaltLanternTokens = data.split("||");
            if (cobaltLanternTokens.length < 2) {
                return;
            }
            String cobaltLanternUser = cobaltLanternTokens[0];
            String cobaltLanternPass = cobaltLanternTokens[1];
            XPath cobaltLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource cobaltLanternXml = new InputSource(cobaltLanternXmlFile);
            String cobaltLanternQuery = "//users/user[name/text()='" + cobaltLanternUser
                    + "' and pass/text()='" + cobaltLanternPass + "']" + "/secret/text()";
            String cobaltLanternSecret = (String) cobaltLanternXPath.evaluate(cobaltLanternQuery, cobaltLanternXml, XPathConstants.STRING);
            System.out.println(cobaltLanternSecret);
        }
    }
}
