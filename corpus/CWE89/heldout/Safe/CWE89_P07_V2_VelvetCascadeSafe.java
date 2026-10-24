import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_VelvetCascadeSafe {

    public void runVelvetCascade() throws SQLException {
        String data;
        while (true) {
            data = (new CWE89_P07_V2_VelvetCascadeSafeSource()).loadVelvetCascade();
            break;
        }
        Connection velvetCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetCascade");
        Statement velvetCascadeStatement = null;
        ResultSet velvetCascadeRows = null;
        try {
            velvetCascadeStatement = velvetCascadeConnection.createStatement();
            velvetCascadeRows = velvetCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetCascadeRows.getRow());
        } finally {
            if (velvetCascadeRows != null) {
                velvetCascadeRows.close();
            }
            if (velvetCascadeStatement != null) {
                velvetCascadeStatement.close();
            }
            velvetCascadeConnection.close();
        }
    }
}

class CWE89_P07_V2_VelvetCascadeSafeSource {
    public String loadVelvetCascade() {
        String data;
        data = "foo";
        return data;
    }
}
