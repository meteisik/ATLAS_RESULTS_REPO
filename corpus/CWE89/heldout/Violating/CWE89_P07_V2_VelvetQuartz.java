import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_VelvetQuartz {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runVelvetQuartz() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = (new CWE89_P07_V2_VelvetQuartzSource()).loadVelvetQuartz();
        } else {
            data = null;
        }
        Connection velvetQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetQuartz");
        Statement velvetQuartzStatement = null;
        ResultSet velvetQuartzRows = null;
        try {
            velvetQuartzStatement = velvetQuartzConnection.createStatement();
            velvetQuartzRows = velvetQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetQuartzRows.getRow());
        } finally {
            if (velvetQuartzRows != null) {
                velvetQuartzRows.close();
            }
            if (velvetQuartzStatement != null) {
                velvetQuartzStatement.close();
            }
            velvetQuartzConnection.close();
        }
    }
}

class CWE89_P07_V2_VelvetQuartzSource {
    public String loadVelvetQuartz() {
        String data;
        data = System.getenv("VELVET_QUARTZ_FILTER");
        return data;
    }
}
