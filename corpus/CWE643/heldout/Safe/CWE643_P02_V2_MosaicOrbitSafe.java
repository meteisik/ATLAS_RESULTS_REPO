import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_MosaicOrbitSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runMosaicOrbit() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_FIVE == 5) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String mosaicOrbitXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                mosaicOrbitXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                mosaicOrbitXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] mosaicOrbitTokens = data.split("||");
                if (mosaicOrbitTokens.length < 2) {
                    return;
                }
                String mosaicOrbitUser = mosaicOrbitTokens[0];
                String mosaicOrbitPass = mosaicOrbitTokens[1];
                XPath mosaicOrbitXPath = XPathFactory.newInstance().newXPath();
                InputSource mosaicOrbitXml = new InputSource(mosaicOrbitXmlFile);
                String mosaicOrbitQuery = "//users/user[name/text()='" + mosaicOrbitUser
                        + "' and pass/text()='" + mosaicOrbitPass + "']" + "/secret/text()";
                String mosaicOrbitSecret = (String) mosaicOrbitXPath.evaluate(mosaicOrbitQuery, mosaicOrbitXml, XPathConstants.STRING);
                System.out.println(mosaicOrbitSecret);
            }
        }
    }
}
