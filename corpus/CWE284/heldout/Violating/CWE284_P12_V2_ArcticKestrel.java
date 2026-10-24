import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_ArcticKestrel {

    public void deleteArcticKestrelAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("ARCTIC_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_ArcticKestrelBase baseObject = new CWE284_P12_V2_ArcticKestrelRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_ArcticKestrelBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_ArcticKestrelRemover extends CWE284_P12_V2_ArcticKestrelBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection arcticKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticKestrel");
        try {
            PreparedStatement arcticKestrelDelete = arcticKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticKestrelDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                arcticKestrelDelete.executeUpdate();
            }
        } finally {
            arcticKestrelConnection.close();
        }
    }
}
