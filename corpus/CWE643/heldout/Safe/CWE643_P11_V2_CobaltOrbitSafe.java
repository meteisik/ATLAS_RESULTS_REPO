import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_CobaltOrbitSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runCobaltOrbit() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_CobaltOrbitSafeSink()).sinkCobaltOrbit(dataHashMap);
    }
}

class CWE643_P11_V2_CobaltOrbitSafeSink {

    public void sinkCobaltOrbit(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String cobaltOrbitXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            cobaltOrbitXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            cobaltOrbitXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] cobaltOrbitTokens = data.split("||");
            if (cobaltOrbitTokens.length < 2) {
                return;
            }
            String cobaltOrbitUser = cobaltOrbitTokens[0];
            String cobaltOrbitPass = cobaltOrbitTokens[1];
            XPath cobaltOrbitXPath = XPathFactory.newInstance().newXPath();
            InputSource cobaltOrbitXml = new InputSource(cobaltOrbitXmlFile);
            String cobaltOrbitQuery = "//users/user[name/text()='" + cobaltOrbitUser
                    + "' and pass/text()='" + cobaltOrbitPass + "']" + "/secret/text()";
            String cobaltOrbitSecret = (String) cobaltOrbitXPath.evaluate(cobaltOrbitQuery, cobaltOrbitXml, XPathConstants.STRING);
            System.out.println(cobaltOrbitSecret);
        }
    }
}
