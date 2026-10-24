import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_SilentHarborSafe {

    public void runSilentHarbor() throws XPathExpressionException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_SilentHarborSafeSink()).sinkSilentHarbor(dataHashMap);
    }
}

class CWE643_P11_V1_SilentHarborSafeSink {

    public void sinkSilentHarbor(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String silentHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentHarborTokens = data.split("||");
            if (silentHarborTokens.length < 2) {
                return;
            }
            String silentHarborUser = silentHarborTokens[0];
            String silentHarborPass = silentHarborTokens[1];
            XPath silentHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource silentHarborXml = new InputSource(silentHarborXmlFile);
            String silentHarborQuery = "//users/user[name/text()='" + silentHarborUser
                    + "' and pass/text()='" + silentHarborPass + "']" + "/secret/text()";
            String silentHarborSecret = (String) silentHarborXPath.evaluate(silentHarborQuery, silentHarborXml, XPathConstants.STRING);
            System.out.println(silentHarborSecret);
        }
    }
}
