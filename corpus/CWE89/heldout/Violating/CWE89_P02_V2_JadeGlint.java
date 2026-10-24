import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_JadeGlint {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runJadeGlint() throws SQLException {
        String dataCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_TRUE) {
                data = System.getenv("JADE_GLINT_FILTER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection jadeGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeGlint");
            Statement jadeGlintStatement = null;
            ResultSet jadeGlintRows = null;
            try {
                jadeGlintStatement = jadeGlintConnection.createStatement();
                jadeGlintRows = jadeGlintStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(jadeGlintRows.getRow());
            } finally {
                if (jadeGlintRows != null) {
                    jadeGlintRows.close();
                }
                if (jadeGlintStatement != null) {
                    jadeGlintStatement.close();
                }
                jadeGlintConnection.close();
            }
        }
    }
}
