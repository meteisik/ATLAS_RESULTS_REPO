import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_VelvetFlareSafe {

    public void runVelvetFlare() throws SQLException {
        String data;
        if (true) {
            data = (new CWE89_P07_V2_VelvetFlareSafeSource()).loadVelvetFlare();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_VelvetFlareSafeSource {
    public String loadVelvetFlare() {
        String data;
        data = "foo";
        return data;
    }
}
