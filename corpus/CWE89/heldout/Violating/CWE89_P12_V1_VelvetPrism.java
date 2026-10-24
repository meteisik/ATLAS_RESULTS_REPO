import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetPrism {

    public void runVelvetPrism() throws SQLException {
        String data;
        data = System.getenv("VELVET_PRISM_FILTER");
        CWE89_P12_V1_VelvetPrismBase baseObject = new CWE89_P12_V1_VelvetPrismSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetPrismBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetPrismSink extends CWE89_P12_V1_VelvetPrismBase {
    public void action(String data) throws SQLException {
        Connection velvetPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetPrism");
        Statement velvetPrismStatement = null;
        ResultSet velvetPrismRows = null;
        try {
            velvetPrismStatement = velvetPrismConnection.createStatement();
            velvetPrismRows = velvetPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetPrismRows.getRow());
        } finally {
            if (velvetPrismRows != null) {
                velvetPrismRows.close();
            }
            if (velvetPrismStatement != null) {
                velvetPrismStatement.close();
            }
            velvetPrismConnection.close();
        }
    }
}
