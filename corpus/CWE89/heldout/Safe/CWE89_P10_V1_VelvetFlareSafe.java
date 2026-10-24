import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VelvetFlareSafe {

    public static String data;

    public void runVelvetFlare() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_VelvetFlareSafeSink()).queryVelvetFlare();
    }
}

class CWE89_P10_V1_VelvetFlareSafeSink {
    public void queryVelvetFlare() throws SQLException {
        String data = CWE89_P10_V1_VelvetFlareSafe.data;
        Connection velvetFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetFlare");
        Statement velvetFlareStatement = null;
        ResultSet velvetFlareRows = null;
        try {
            velvetFlareStatement = velvetFlareConnection.createStatement();
            velvetFlareRows = velvetFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetFlareRows.getRow());
        } finally {
            if (velvetFlareRows != null) {
                velvetFlareRows.close();
            }
            if (velvetFlareStatement != null) {
                velvetFlareStatement.close();
            }
            velvetFlareConnection.close();
        }
    }
}
