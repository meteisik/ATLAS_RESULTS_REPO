import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SaffronFlareSafe {

    public static String data;

    public void runSaffronFlare() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_SaffronFlareSafeSink()).querySaffronFlare();
    }
}

class CWE89_P10_V1_SaffronFlareSafeSink {
    public void querySaffronFlare() throws SQLException {
        String data = CWE89_P10_V1_SaffronFlareSafe.data;
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
