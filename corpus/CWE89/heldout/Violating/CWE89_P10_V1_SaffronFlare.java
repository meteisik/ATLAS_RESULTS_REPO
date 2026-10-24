import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SaffronFlare {

    public static String data;

    public void runSaffronFlare() throws SQLException {
        data = System.getenv("SAFFRON_FLARE_FILTER");
        (new CWE89_P10_V1_SaffronFlareSink()).querySaffronFlare();
    }
}

class CWE89_P10_V1_SaffronFlareSink {
    public void querySaffronFlare() throws SQLException {
        String data = CWE89_P10_V1_SaffronFlare.data;
        Connection saffronFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronFlare");
        Statement saffronFlareStatement = null;
        ResultSet saffronFlareRows = null;
        try {
            saffronFlareStatement = saffronFlareConnection.createStatement();
            saffronFlareRows = saffronFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronFlareRows.getRow());
        } finally {
            if (saffronFlareRows != null) {
                saffronFlareRows.close();
            }
            if (saffronFlareStatement != null) {
                saffronFlareStatement.close();
            }
            saffronFlareConnection.close();
        }
    }
}
