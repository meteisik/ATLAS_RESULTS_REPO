import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_SilentRaven {

    public void runSilentRaven() throws XPathExpressionException {
        String data;
        data = System.getenv("SILENT_RAVEN_ADD");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_SilentRavenSink()).sinkSilentRaven(dataHashMap);
    }
}

class CWE643_P11_V1_SilentRavenSink {

    public void sinkSilentRaven(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String silentRavenXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentRavenXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentRavenXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentRavenTokens = data.split("||");
            if (silentRavenTokens.length < 2) {
                return;
            }
            String silentRavenUser = silentRavenTokens[0];
            String silentRavenPass = silentRavenTokens[1];
            XPath silentRavenXPath = XPathFactory.newInstance().newXPath();
            InputSource silentRavenXml = new InputSource(silentRavenXmlFile);
            String silentRavenQuery = "//users/user[name/text()='" + silentRavenUser
                    + "' and pass/text()='" + silentRavenPass + "']" + "/secret/text()";
            String silentRavenSecret = (String) silentRavenXPath.evaluate(silentRavenQuery, silentRavenXml, XPathConstants.STRING);
            System.out.println(silentRavenSecret);
        }
    }
}
