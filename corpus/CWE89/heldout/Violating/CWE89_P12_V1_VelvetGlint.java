import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetGlint {

    public void runVelvetGlint() throws SQLException {
        String data;
        data = System.getenv("VELVET_GLINT_FILTER");
        CWE89_P12_V1_VelvetGlintBase baseObject = new CWE89_P12_V1_VelvetGlintSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetGlintBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetGlintSink extends CWE89_P12_V1_VelvetGlintBase {
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
