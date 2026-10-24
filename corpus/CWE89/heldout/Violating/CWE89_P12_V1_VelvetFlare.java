import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetFlare {

    public void runVelvetFlare() throws SQLException {
        String data;
        data = System.getenv("VELVET_FLARE_FILTER");
        CWE89_P12_V1_VelvetFlareBase baseObject = new CWE89_P12_V1_VelvetFlareSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetFlareBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetFlareSink extends CWE89_P12_V1_VelvetFlareBase {
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
