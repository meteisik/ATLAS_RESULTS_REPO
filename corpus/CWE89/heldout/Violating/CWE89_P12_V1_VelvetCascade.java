import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetCascade {

    public void runVelvetCascade() throws SQLException {
        String data;
        data = System.getenv("VELVET_CASCADE_FILTER");
        CWE89_P12_V1_VelvetCascadeBase baseObject = new CWE89_P12_V1_VelvetCascadeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetCascadeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetCascadeSink extends CWE89_P12_V1_VelvetCascadeBase {
    public void action(String data) throws SQLException {
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
