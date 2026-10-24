import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VelvetCascade {

    public static String data;

    public void runVelvetCascade() throws SQLException {
        data = System.getenv("VELVET_CASCADE_FILTER");
        (new CWE89_P10_V1_VelvetCascadeSink()).queryVelvetCascade();
    }
}

class CWE89_P10_V1_VelvetCascadeSink {
    public void queryVelvetCascade() throws SQLException {
        String data = CWE89_P10_V1_VelvetCascade.data;
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
