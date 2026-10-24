import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VelvetGlint {

    public static String data;

    public void runVelvetGlint() throws SQLException {
        data = System.getenv("VELVET_GLINT_FILTER");
        (new CWE89_P10_V1_VelvetGlintSink()).queryVelvetGlint();
    }
}

class CWE89_P10_V1_VelvetGlintSink {
    public void queryVelvetGlint() throws SQLException {
        String data = CWE89_P10_V1_VelvetGlint.data;
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
