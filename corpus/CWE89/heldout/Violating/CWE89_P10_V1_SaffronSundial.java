import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SaffronSundial {

    public static String data;

    public void runSaffronSundial() throws SQLException {
        data = System.getenv("SAFFRON_SUNDIAL_FILTER");
        (new CWE89_P10_V1_SaffronSundialSink()).querySaffronSundial();
    }
}

class CWE89_P10_V1_SaffronSundialSink {
    public void querySaffronSundial() throws SQLException {
        String data = CWE89_P10_V1_SaffronSundial.data;
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
