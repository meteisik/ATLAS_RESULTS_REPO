import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_MosaicRaven {

    private String mosaicRavenAccountId;

    private boolean mosaicRavenAuthorized;

    private void applyMosaicRavenDeletion() throws SQLException {
        String data = mosaicRavenAccountId;
        boolean authorized = mosaicRavenAuthorized;
        Connection mosaicRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicRaven");
        try {
            PreparedStatement mosaicRavenDelete = mosaicRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicRavenDelete.setString(1, data);
            mosaicRavenDelete.executeUpdate();
        } finally {
            mosaicRavenConnection.close();
        }
    }

    public void deleteMosaicRavenAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_RAVEN_ACCOUNT_ID");
        mosaicRavenAccountId = data;
        mosaicRavenAuthorized = isAuthorized(data);
        applyMosaicRavenDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
