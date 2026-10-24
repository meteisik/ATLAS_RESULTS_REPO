import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V1_IvoryComet {

    private String ivoryCometData;

    private void sinkIvoryComet() throws XPathExpressionException {
        String data = ivoryCometData;
        String ivoryCometXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            ivoryCometXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            ivoryCometXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] ivoryCometTokens = data.split("||");
            if (ivoryCometTokens.length < 2) {
                return;
            }
            String ivoryCometUser = ivoryCometTokens[0];
            String ivoryCometPass = ivoryCometTokens[1];
            XPath ivoryCometXPath = XPathFactory.newInstance().newXPath();
            InputSource ivoryCometXml = new InputSource(ivoryCometXmlFile);
            String ivoryCometQuery = "//users/user[name/text()='" + ivoryCometUser
                    + "' and pass/text()='" + ivoryCometPass + "']" + "/secret/text()";
            String ivoryCometSecret = (String) ivoryCometXPath.evaluate(ivoryCometQuery, ivoryCometXml, XPathConstants.STRING);
            System.out.println(ivoryCometSecret);
        }
    }

    public void runIvoryComet() throws XPathExpressionException {
        String data;
        data = System.getenv("IVORY_COMET_ADD");
        ivoryCometData = data;
        sinkIvoryComet();
    }
}
