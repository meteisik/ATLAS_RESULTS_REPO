import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_SilentLantern {

    public void runSilentLantern() throws XPathExpressionException {
        String data;
        data = System.getenv("SILENT_LANTERN_ADD");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_SilentLanternSink()).sinkSilentLantern(dataHashMap);
    }
}

class CWE643_P11_V1_SilentLanternSink {

    public void sinkSilentLantern(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String silentLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentLanternTokens = data.split("||");
            if (silentLanternTokens.length < 2) {
                return;
            }
            String silentLanternUser = silentLanternTokens[0];
            String silentLanternPass = silentLanternTokens[1];
            XPath silentLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource silentLanternXml = new InputSource(silentLanternXmlFile);
            String silentLanternQuery = "//users/user[name/text()='" + silentLanternUser
                    + "' and pass/text()='" + silentLanternPass + "']" + "/secret/text()";
            String silentLanternSecret = (String) silentLanternXPath.evaluate(silentLanternQuery, silentLanternXml, XPathConstants.STRING);
            System.out.println(silentLanternSecret);
        }
    }
}
