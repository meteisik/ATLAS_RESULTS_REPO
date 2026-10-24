import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_SaffronFlare {
    private static boolean privateReturnsTrue() { return true; }

    private String saffronFlareData;

    private void querySaffronFlare() throws SQLException {
        String data = saffronFlareData;
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

    public void runSaffronFlare() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("SAFFRON_FLARE_FILTER");
        } else {
            data = null;
        }
        saffronFlareData = data;
        querySaffronFlare();
    }
}
