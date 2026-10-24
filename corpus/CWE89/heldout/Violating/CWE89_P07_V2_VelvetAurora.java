import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_VelvetAurora {

    public void runVelvetAurora() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = (new CWE89_P07_V2_VelvetAuroraSource()).loadVelvetAurora();
            break;
        default:
            data = null;
            break;
        }
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

class CWE89_P07_V2_VelvetAuroraSource {
    public String loadVelvetAurora() {
        String data;
        data = System.getenv("VELVET_AURORA_FILTER");
        return data;
    }
}
