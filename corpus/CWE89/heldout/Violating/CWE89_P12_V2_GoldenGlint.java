import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_GoldenGlint {
    private static int privateFive = 5;

    public void runGoldenGlint() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("GOLDEN_GLINT_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_GoldenGlintBase baseObject = new CWE89_P12_V2_GoldenGlintSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_GoldenGlintBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_GoldenGlintSink extends CWE89_P12_V2_GoldenGlintBase {
    public void action(String data) throws SQLException {
        Connection goldenGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenGlint");
        Statement goldenGlintStatement = null;
        ResultSet goldenGlintRows = null;
        try {
            goldenGlintStatement = goldenGlintConnection.createStatement();
            goldenGlintRows = goldenGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenGlintRows.getRow());
        } finally {
            if (goldenGlintRows != null) {
                goldenGlintRows.close();
            }
            if (goldenGlintStatement != null) {
                goldenGlintStatement.close();
            }
            goldenGlintConnection.close();
        }
    }
}
