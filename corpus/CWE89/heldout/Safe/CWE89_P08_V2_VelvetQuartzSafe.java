import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V2_VelvetQuartzSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runVelvetQuartz() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V2_VelvetQuartzSafeSink()).queryVelvetQuartz(dataArray);
    }
}

class CWE89_P08_V2_VelvetQuartzSafeSink {
    public void queryVelvetQuartz(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
