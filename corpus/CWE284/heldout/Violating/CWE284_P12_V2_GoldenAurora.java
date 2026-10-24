import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_GoldenAurora {

    public void deleteGoldenAuroraAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("GOLDEN_AURORA_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_GoldenAuroraBase baseObject = new CWE284_P12_V2_GoldenAuroraRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_GoldenAuroraBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_GoldenAuroraRemover extends CWE284_P12_V2_GoldenAuroraBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection goldenAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenAurora");
        try {
            PreparedStatement goldenAuroraDelete = goldenAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenAuroraDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenAuroraDelete.executeUpdate();
            }
        } finally {
            goldenAuroraConnection.close();
        }
    }
}
