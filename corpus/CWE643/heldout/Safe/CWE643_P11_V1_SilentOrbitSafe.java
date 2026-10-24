import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_SilentOrbitSafe {

    public void runSilentOrbit() throws XPathExpressionException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_SilentOrbitSafeSink()).sinkSilentOrbit(dataHashMap);
    }
}

class CWE643_P11_V1_SilentOrbitSafeSink {

    public void sinkSilentOrbit(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String silentOrbitXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentOrbitXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentOrbitXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentOrbitTokens = data.split("||");
            if (silentOrbitTokens.length < 2) {
                return;
            }
            String silentOrbitUser = silentOrbitTokens[0];
            String silentOrbitPass = silentOrbitTokens[1];
            XPath silentOrbitXPath = XPathFactory.newInstance().newXPath();
            InputSource silentOrbitXml = new InputSource(silentOrbitXmlFile);
            String silentOrbitQuery = "//users/user[name/text()='" + silentOrbitUser
                    + "' and pass/text()='" + silentOrbitPass + "']" + "/secret/text()";
            String silentOrbitSecret = (String) silentOrbitXPath.evaluate(silentOrbitQuery, silentOrbitXml, XPathConstants.STRING);
            System.out.println(silentOrbitSecret);
        }
    }
}
