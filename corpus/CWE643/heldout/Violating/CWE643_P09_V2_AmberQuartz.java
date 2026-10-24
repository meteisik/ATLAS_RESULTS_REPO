import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_AmberQuartz {
    private static boolean privateTrue = true;

    static class Container {
        public String containerOne;
    }

    public void runAmberQuartz() throws XPathExpressionException {
        String data;
        if (privateTrue) {
            data = System.getenv("AMBER_QUARTZ_ADD");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_AmberQuartzSink()).sinkAmberQuartz(dataContainer);
    }
}

class CWE643_P09_V2_AmberQuartzSink {

    public void sinkAmberQuartz(CWE643_P09_V2_AmberQuartz.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String amberQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberQuartzTokens = data.split("||");
            if (amberQuartzTokens.length < 2) {
                return;
            }
            String amberQuartzUser = amberQuartzTokens[0];
            String amberQuartzPass = amberQuartzTokens[1];
            XPath amberQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource amberQuartzXml = new InputSource(amberQuartzXmlFile);
            String amberQuartzQuery = "//users/user[name/text()='" + amberQuartzUser
                    + "' and pass/text()='" + amberQuartzPass + "']" + "/secret/text()";
            String amberQuartzSecret = (String) amberQuartzXPath.evaluate(amberQuartzQuery, amberQuartzXml, XPathConstants.STRING);
            System.out.println(amberQuartzSecret);
        }
    }
}
