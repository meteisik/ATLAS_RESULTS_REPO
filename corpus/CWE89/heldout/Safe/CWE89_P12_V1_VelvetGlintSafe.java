import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetGlintSafe {

    public void runVelvetGlint() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_VelvetGlintSafeBase baseObject = new CWE89_P12_V1_VelvetGlintSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetGlintSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetGlintSafeSink extends CWE89_P12_V1_VelvetGlintSafeBase {
    public void action(String data) throws SQLException {
        Connection velvetGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetGlint");
        Statement velvetGlintStatement = null;
        ResultSet velvetGlintRows = null;
        try {
            velvetGlintStatement = velvetGlintConnection.createStatement();
            velvetGlintRows = velvetGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetGlintRows.getRow());
        } finally {
            if (velvetGlintRows != null) {
                velvetGlintRows.close();
            }
            if (velvetGlintStatement != null) {
                velvetGlintStatement.close();
            }
            velvetGlintConnection.close();
        }
    }
}
