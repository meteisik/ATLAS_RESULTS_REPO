import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetFlareSafe {

    public void runVelvetFlare() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_VelvetFlareSafeBase baseObject = new CWE89_P12_V1_VelvetFlareSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetFlareSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetFlareSafeSink extends CWE89_P12_V1_VelvetFlareSafeBase {
    public void action(String data) throws SQLException {
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
