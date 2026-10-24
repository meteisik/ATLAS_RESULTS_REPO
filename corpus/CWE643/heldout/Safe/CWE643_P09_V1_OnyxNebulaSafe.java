import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_OnyxNebulaSafe {

    static class Container {
        public String containerOne;
    }

    public void runOnyxNebula() throws XPathExpressionException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_OnyxNebulaSafeSink()).sinkOnyxNebula(dataContainer);
    }
}

class CWE643_P09_V1_OnyxNebulaSafeSink {

    public void sinkOnyxNebula(CWE643_P09_V1_OnyxNebulaSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String onyxNebulaXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            onyxNebulaXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            onyxNebulaXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] onyxNebulaTokens = data.split("||");
            if (onyxNebulaTokens.length < 2) {
                return;
            }
            String onyxNebulaUser = onyxNebulaTokens[0];
            String onyxNebulaPass = onyxNebulaTokens[1];
            XPath onyxNebulaXPath = XPathFactory.newInstance().newXPath();
            InputSource onyxNebulaXml = new InputSource(onyxNebulaXmlFile);
            String onyxNebulaQuery = "//users/user[name/text()='" + onyxNebulaUser
                    + "' and pass/text()='" + onyxNebulaPass + "']" + "/secret/text()";
            String onyxNebulaSecret = (String) onyxNebulaXPath.evaluate(onyxNebulaQuery, onyxNebulaXml, XPathConstants.STRING);
            System.out.println(onyxNebulaSecret);
        }
    }
}
