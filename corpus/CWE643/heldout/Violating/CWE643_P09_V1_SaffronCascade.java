import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V1_SaffronCascade {

    static class Container {
        public String containerOne;
    }

    public void runSaffronCascade() throws XPathExpressionException {
        String data;
        data = System.getenv("SAFFRON_CASCADE_ADD");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V1_SaffronCascadeSink()).sinkSaffronCascade(dataContainer);
    }
}

class CWE643_P09_V1_SaffronCascadeSink {

    public void sinkSaffronCascade(CWE643_P09_V1_SaffronCascade.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String saffronCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronCascadeTokens = data.split("||");
            if (saffronCascadeTokens.length < 2) {
                return;
            }
            String saffronCascadeUser = saffronCascadeTokens[0];
            String saffronCascadePass = saffronCascadeTokens[1];
            XPath saffronCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronCascadeXml = new InputSource(saffronCascadeXmlFile);
            String saffronCascadeQuery = "//users/user[name/text()='" + saffronCascadeUser
                    + "' and pass/text()='" + saffronCascadePass + "']" + "/secret/text()";
            String saffronCascadeSecret = (String) saffronCascadeXPath.evaluate(saffronCascadeQuery, saffronCascadeXml, XPathConstants.STRING);
            System.out.println(saffronCascadeSecret);
        }
    }
}
