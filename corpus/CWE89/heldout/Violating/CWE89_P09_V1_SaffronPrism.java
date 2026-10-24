import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_SaffronPrism {

    static class Container {
        public String containerOne;
    }

    public void runSaffronPrism() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_PRISM_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_SaffronPrismSink()).querySaffronPrism(dataContainer);
    }
}

class CWE89_P09_V1_SaffronPrismSink {
    public void querySaffronPrism(CWE89_P09_V1_SaffronPrism.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection saffronPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronPrism");
        Statement saffronPrismStatement = null;
        ResultSet saffronPrismRows = null;
        try {
            saffronPrismStatement = saffronPrismConnection.createStatement();
            saffronPrismRows = saffronPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronPrismRows.getRow());
        } finally {
            if (saffronPrismRows != null) {
                saffronPrismRows.close();
            }
            if (saffronPrismStatement != null) {
                saffronPrismStatement.close();
            }
            saffronPrismConnection.close();
        }
    }
}
