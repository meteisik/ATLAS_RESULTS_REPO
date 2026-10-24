import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_SaffronSundial {

    static class Container {
        public String containerOne;
    }

    public void runSaffronSundial() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_SUNDIAL_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_SaffronSundialSink()).querySaffronSundial(dataContainer);
    }
}

class CWE89_P09_V1_SaffronSundialSink {
    public void querySaffronSundial(CWE89_P09_V1_SaffronSundial.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection saffronSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSundial");
        Statement saffronSundialStatement = null;
        ResultSet saffronSundialRows = null;
        try {
            saffronSundialStatement = saffronSundialConnection.createStatement();
            saffronSundialRows = saffronSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronSundialRows.getRow());
        } finally {
            if (saffronSundialRows != null) {
                saffronSundialRows.close();
            }
            if (saffronSundialStatement != null) {
                saffronSundialStatement.close();
            }
            saffronSundialConnection.close();
        }
    }
}
