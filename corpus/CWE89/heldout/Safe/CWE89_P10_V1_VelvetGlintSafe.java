import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VelvetGlintSafe {

    public static String data;

    public void runVelvetGlint() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_VelvetGlintSafeSink()).queryVelvetGlint();
    }
}

class CWE89_P10_V1_VelvetGlintSafeSink {
    public void queryVelvetGlint() throws SQLException {
        String data = CWE89_P10_V1_VelvetGlintSafe.data;
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
