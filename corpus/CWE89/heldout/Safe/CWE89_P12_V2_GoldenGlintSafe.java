import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_GoldenGlintSafe {
    private static int privateFive = 5;

    public void runGoldenGlint() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_GoldenGlintSafeBase baseObject = new CWE89_P12_V2_GoldenGlintSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_GoldenGlintSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_GoldenGlintSafeSink extends CWE89_P12_V2_GoldenGlintSafeBase {
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
