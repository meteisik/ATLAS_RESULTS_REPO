import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_SaffronMantis {

    static class Container {
        public String containerOne;
    }

    public void runSaffronMantis() throws XPathExpressionException {
        String data;
        data = System.getenv("SAFFRON_MANTIS_ADD");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_SaffronMantisSink()).sinkSaffronMantis(dataContainer);
    }
}

class CWE643_P09_V1_SaffronMantisSink {

    public void sinkSaffronMantis(CWE643_P09_V1_SaffronMantis.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String saffronMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronMantisTokens = data.split("||");
            if (saffronMantisTokens.length < 2) {
                return;
            }
            String saffronMantisUser = saffronMantisTokens[0];
            String saffronMantisPass = saffronMantisTokens[1];
            XPath saffronMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronMantisXml = new InputSource(saffronMantisXmlFile);
            String saffronMantisQuery = "//users/user[name/text()='" + saffronMantisUser
                    + "' and pass/text()='" + saffronMantisPass + "']" + "/secret/text()";
            String saffronMantisSecret = (String) saffronMantisXPath.evaluate(saffronMantisQuery, saffronMantisXml, XPathConstants.STRING);
            System.out.println(saffronMantisSecret);
        }
    }
}
