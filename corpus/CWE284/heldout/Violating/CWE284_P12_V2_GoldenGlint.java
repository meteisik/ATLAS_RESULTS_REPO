import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_GoldenGlint {
    private static int privateFive = 5;

    public void deleteGoldenGlintAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("GOLDEN_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_GoldenGlintBase baseObject = new CWE284_P12_V2_GoldenGlintRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_GoldenGlintBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_GoldenGlintRemover extends CWE284_P12_V2_GoldenGlintBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection goldenGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenGlint");
        try {
            PreparedStatement goldenGlintDelete = goldenGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenGlintDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenGlintDelete.executeUpdate();
            }
        } finally {
            goldenGlintConnection.close();
        }
    }
}
