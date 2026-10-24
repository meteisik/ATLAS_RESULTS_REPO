import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_VelvetAuroraSafe {

    static class Container {
        public String containerOne;
    }

    public void runVelvetAurora() throws SQLException {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_VelvetAuroraSafeSink()).queryVelvetAurora(dataContainer);
    }
}

class CWE89_P09_V2_VelvetAuroraSafeSink {
    public void queryVelvetAurora(CWE89_P09_V2_VelvetAuroraSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection velvetAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetAurora");
        Statement velvetAuroraStatement = null;
        ResultSet velvetAuroraRows = null;
        try {
            velvetAuroraStatement = velvetAuroraConnection.createStatement();
            velvetAuroraRows = velvetAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetAuroraRows.getRow());
        } finally {
            if (velvetAuroraRows != null) {
                velvetAuroraRows.close();
            }
            if (velvetAuroraStatement != null) {
                velvetAuroraStatement.close();
            }
            velvetAuroraConnection.close();
        }
    }
}
